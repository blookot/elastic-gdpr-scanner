#!/usr/bin/env python

###########################################################
# GDPR scanner, by Vincent Maury
# see https://github.com/blookot/elastic-gdpr-scanner
###########################################################

import socket
import subprocess
import sys
import threading
from queue import Queue
import signal
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import json
import re
import argparse
import ipaddress


# variables and inputs
VERBOSE = False
API_OUTPUT = False
SCAN_FIRST_INDEX_ONLY = False
SCAN_FIRST_PORT_ONLY = False
INVENTORY_ONLY = False
THREAD_TIMEOUT = 240                 # timeout per host, in seconds
DEFAULT_TCP_SOCKET_TIMEOUT = 2              # timeout for port scan, in seconds
DEFAULT_NB_THREADS = 10             # nb of targets to scan in parallel
DEFAULT_TARGET = '127.0.0.1'
DEFAULT_PORT = '9200'
DEFAULT_LOG_FILE = 'es-gdpr-report.csv'



# PII can include driver’s licenses, license plate numbers, VAT codes, heathcare identification numbers, and various other national ID numbers.
# main source: https://ipsec.pl/data-protection/2012/european-personal-data-regexp-patterns.html
# https://github.com/tvfischer/gdpr-data-patterns-detection which is empty...
REGEXES = [
    '[1,2][ ]?[0-9]{2}[ ]?[0,1,2,3,5][0-9][ ]?[0-9]{2}[ ]?[0-9]{3}[ ]?[0-9]{3}[ ]?[0-9]{2}',    # French social security number
    '[0-9]{2}[A-Z]{2}[0-9]{5}',     # French passport number
    '[0-9]{2}[0,1][0-9][0-9]{2}-[A-Z]-[0-9]{5}',    # German Personenkennziffer
    # '[0-9]{3}/?[0-9]{4}/?[0-9]{4}',     # German Steuer-Identifikationsnummer
    '[0-9]{2}[0-9]{2}[0,1][0-9][0-9]{2}[A-Z][0-9]{2}[0-9]',     # German Versicherungsnummer, Rentenversicherungsnummer
    '[0-9,X,M,L,K,Y][0-9]{7}[A-Z]',     # Spanish Documento Nacional de Identidad
    '[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]{1}[0-9]{6}[A-DFM]?',       # UK National Identity Number
    # '[0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4}',       # UK national health security number, but matches certain beats!
    '[0-9]{2}\.?[0-9]{2}\.?[0-9]{2}-[0-9]{3}\.?[0-9]{2}',       # Belgium ID
    '[A-Z]{2}?[ ]?[0-9]{2}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}[ ]?[0-9]{4}',        # EU IBAN
]


# a print_lock is what is used to prevent "double" modification of shared variables.
# this is used so while one thread is using a variable, others cannot access
# it. Once done, the thread releases the print_lock.
# to use it, you want to specify a print_lock per thing you wish to print_lock.
print_lock = threading.Lock()
start_time = time.time()



# handle Ctrl-C to stop
def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


# regex checker func (outputs true when regex match, ie outputs true when *not* compliant)
def regex_checker(jsonDoc):
    # print ('Testing: '+json.dumps(jsonDoc))
    for key, value in iter(jsonDoc.items()):
        if isinstance(value, str):
            for r in REGEXES:
                check = bool(re.search(r, value))
                if VERBOSE:
                    print ('\tCheck '+value+' against regex \''+r+'\': '+str(check))
                if check:
                    return {"result":True, "value":value, "regex":r}
        elif isinstance(value,dict):
            return regex_checker(value)
    return {"result":False, "value":"", "regex":""}


# simple function to return content of a given URL get call
def getUrlContent(url):
    if VERBOSE:
        print ("Calling URL {}".format(url))
    try:
        r = urlopen(Request(url))
    except HTTPError as e:
        print('Code: '+e.code+'. The server couldn\'t fulfill the request: '+url)
        return 0
    except URLError as e:
        print('Reason: '+e.reason+'. We failed to reach a server on this request: '+url)
        return 0
    else:
        if r.code == 200:
            content = json.loads(r.read().decode('utf-8'))
            if API_OUTPUT:
                print (json.dumps(content, sort_keys=True, indent=4, separators=(',', ': ')))
            return content
        else:
            return 0


# port scan function
def portscan(hostname):
    ip = socket.gethostbyname(hostname)
    for port in PORTS:
        if VERBOSE:
            print ("** DEBUG ** Scanning Host: {}, Port {}".format(ip,port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(float(TCP_SOCKET_TIMEOUT))
            s.connect((ip,int(port)))
            s.close()
        except socket.gaierror:
            print ('Hostname could not be resolved. Exiting')
            # pass
        except socket.error:
            print ("Host: {}, Port {}: Closed".format(ip,port))
            # pass
        else:
            if VERBOSE:
                print ("Host: {}, Port {}: Open".format(ip,port))
            # Try getting ES answer
            esAnswer = getUrlContent("http://"+ip+":"+port)
            if esAnswer != 0:
                if 'cluster_name' in esAnswer:
                    clusterName = esAnswer['cluster_name']
                else:
                    clusterName = "null"
                if 'name' in esAnswer:
                    name = esAnswer['name']
                else:
                    name = "null"
                if 'version' in esAnswer:
                    if 'number' in esAnswer['version']:
                        versionNumber = esAnswer['version']['number']
                    else:
                        versionNumber = 'null'
                else:
                    versionNumber = 'null'
                # then grab stats on node from /_stats/docs,store
                esAnswer = getUrlContent("http://"+ip+":"+port+'/_stats/docs,store')
                if esAnswer != 0:
                    if '_all' in esAnswer:
                        if 'total' in esAnswer['_all']:
                            totalDocs = esAnswer['_all']['total']['docs']['count']
                            totalSize = int(int(esAnswer['_all']['total']['store']['size_in_bytes'])/(1024*1024))
                        else:
                            totalDocs = 'null'
                            totalSize = 'null'
                    else:
                        totalDocs = 'null'
                        totalSize = 'null'
                    print ("Found Host: {}, Port {}, Cluster name: {}, Name: {}, Version: {}, Total number of docs: {}, Total size (MB): {}".format(ip, port, clusterName, name, versionNumber, totalDocs, totalSize))
                    logFile.write("{},{},{},{},{},{},{}\r\n".format(ip, port, clusterName, name, versionNumber, totalDocs, totalSize))
                    if not INVENTORY_ONLY:
                        # then explore indices
                        # /_cat/indices introduced in 1.3, not working on v0.90 (thus relying on node stats...)
                        if 'indices' in esAnswer:
                            for index, indexDetails in iter(esAnswer['indices'].items()):
                                if VERBOSE:
                                    print ("** Testing index {}".format(index))
                                # consider non-internal indices
                                if index[:1] != '.':
                                    # grab index stats
                                    # print (json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
                                    indexNbDocs = indexDetails['total']['docs']['count']
                                    indexSize = int(int(indexDetails['total']['store']['size_in_bytes'])/(1024*1024))
                                    # then get first doc : /[index]/_search?size=1
                                    esDocs = getUrlContent("http://"+ip+":"+port+"/"+index+"/_search?size=1")
                                    if esDocs != 0:
                                        # check if at least 1 document
                                        if esDocs['hits']['total'] == 0:
                                            if VERBOSE:
                                                print ("No document found in index "+index)
                                            logFile.write("{},{},{},{},{},{},{},{},{},{},N/A (no doc)\r\n".format(ip, port, clusterName, name, versionNumber, totalDocs, totalSize, index, indexNbDocs, indexSize))
                                        else:
                                            # get source doc
                                            try:
                                                source = esDocs['hits']['hits'][0]['_source']
                                            except:
                                                print ('Couldn\'t get document from index '+index)
                                            else:
                                                # check for compliance calling regex checker func (outputs true when regex match, ie *not* compliant)
                                                rgpdCheck = regex_checker(source)
                                                if VERBOSE:
                                                    print ('** Testing index {}, result: {}'.format(index, rgpdCheck['result']))
                                                else:
                                                    if rgpdCheck['result']:
                                                        # display uncompliant indices even if not verbose
                                                        print ("** Host: {}, Port {}, Cluster name: {}, Name: {}, Version: {} - Index {} not compliant! (value '{}' matched regex '{}')".format(ip, port, clusterName, name, versionNumber, index, rgpdCheck['value'], rgpdCheck['regex']))
                                                # log in file anyway
                                                logFile.write("{},{},{},{},{},{},{},{},{},{},{},{},{}\r\n".format(ip, port, clusterName, name, versionNumber, totalDocs, totalSize, index, indexNbDocs, indexSize, not(rgpdCheck['result']), rgpdCheck['value'], rgpdCheck['regex']))
                                    # scan only first index to go faster
                                    if SCAN_FIRST_INDEX_ONLY:
                                        break
                        # indices listing didn't work
                        else:
                            print ('Couldn\'t list indices')
        # scan first port only
        if SCAN_FIRST_PORT_ONLY:
            break




# Getting arguments
parser = argparse.ArgumentParser(description='Scan Elasticsearch clusters to check for GDPR compliance.')
parser.add_argument('--target', action='store', default='', help='IP range (CIDR format, eg 10.50.3.0/24) to scan (default: localhost)')
parser.add_argument('--port', action='store', default='', help='Port where Elasticsearch is running (default: 9200)')
parser.add_argument('--regex', action='store', default='', help='Specific regex to look for')
parser.add_argument('--nb-threads', action='store', default='', dest='nbthreads', help='Number of hosts to scan in parallel (default: 10)')
parser.add_argument('--socket-timeout', action='store', default='', dest='stimeout', help='Seconds to wait for each host/port scanned. Set it to 2 on the Internet, 0.5 in local networks (default: 2)')
parser.add_argument('--no-scan', action='store_true', default=False, dest='noscan', help='Inventory only (no regex matching)')
parser.add_argument('--out', action='store', default='', help='Log file with verbose output (default: es-gdpr-report.csv)')
parser.add_argument('--verbose', action='store_true', default=False, help='Turn on verbose output in console')
results = parser.parse_args()
if results.target != '':
    TARGETS = results.target
else:
    TARGETS = DEFAULT_TARGET
if results.port != '':
    PORTS = [results.port]
else:
    PORTS = [DEFAULT_PORT]
if results.regex != '':
    list.append(REGEXES, results.regex)
if results.nbthreads != '':
    NB_THREADS = results.nbthreads
else:
    NB_THREADS = DEFAULT_NB_THREADS
if results.stimeout != '':
    TCP_SOCKET_TIMEOUT = results.stimeout
else:
    TCP_SOCKET_TIMEOUT = DEFAULT_TCP_SOCKET_TIMEOUT
INVENTORY_ONLY = results.noscan
if results.out != '':
    LOG_FILE = results.out
else:
    LOG_FILE = DEFAULT_LOG_FILE
VERBOSE = results.verbose



# prepare log file
logFile = open(LOG_FILE,"w")
if INVENTORY_ONLY:
    logFile.write("Host,Port,Cluster_name,Name,Version,Total_nb_docs,Total_size_in_MB\r\n")
else:
    logFile.write("Host,Port,Cluster_name,Name,Version,Total_nb_docs,Total_size_in_MB,Index,Index_nb_docs,Index_size_in_MB,Compliant,Value,Regex\r\n")


# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # gets a worker from the queue
        worker = q.get(True,THREAD_TIMEOUT)
        # Run the example job with the avail worker in queue (thread)
        try:
            portscan(worker)
        except:
            print ("Error in thread...")
        # completed with the job
        q.task_done()

# Create the queue and threader
q = Queue()

# how many threads are we going to allow for
for x in range(NB_THREADS):
     t = threading.Thread(target=threader)
     # classifying as a daemon, so they will die when the main dies
     t.daemon = True
     # begins, must come after daemon definition
     t.start()


# start workers for each port
for target in ipaddress.IPv4Network(TARGETS):
    q.put(str(target))

# wait until the thread terminates.
q.join()


logFile.close()
print('')
print("Scan complete in {} seconds!".format(int(time.time() - start_time)))
