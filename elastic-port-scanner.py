#!/usr/bin/env python

###########################################################
# GDPR scanner, by Vincent Maury
# see https://github.com/blookot/elastic-gdpr-scanner
###########################################################


# This script requires Python 3!
import sys
MIN_PYTHON = (3, 0)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


import socket
import sys
import threading
from queue import Queue
import signal
import time
from urllib.request import Request, urlopen, HTTPPasswordMgrWithDefaultRealm, HTTPBasicAuthHandler, build_opener, install_opener
from urllib.error import URLError, HTTPError
import json
import argparse
import ipaddress



# variables and inputs
VERBOSE = False
THREAD_TIMEOUT = 240                    # timeout per host, in seconds
DEFAULT_TCP_SOCKET_TIMEOUT = 2          # timeout for port scan, in seconds
DEFAULT_NB_THREADS = 10                 # nb of targets to scan in parallel
DEFAULT_TARGET = '127.0.0.1'
DEFAULT_PORT = '9200'
DEFAULT_USER = 'elastic'
DEFAULT_PASSWORD = 'changeme'
DEFAULT_UA = 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17'
DEFAULT_OUTPUT_FILE = 'targets.json'
DEFAULT_LOG_FILE = 'es-scanner.csv'
HTTP_OK = 0
HTTP_ERROR = -1
HTTP_UNAUTHORIZED = -2

targets = DEFAULT_TARGET
ports = [DEFAULT_PORT]
user = DEFAULT_USER
pwd = DEFAULT_PASSWORD

# json of targets for output
outputTargets = {"targets": []}

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



# main scanning function
def portscan(hostname):
    ip = socket.gethostbyname(hostname)
    for port in ports:
        if VERBOSE:
            print ("** DEBUG ** Scanning Host: {}, Port {}".format(ip,port))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(float(TCP_SOCKET_TIMEOUT))
            s.connect((ip,int(port)))
            s.close()
        except socket.gaierror:
            print ('(Hostname could not be resolved. Skipping)')
            # pass
        except socket.error:
            print ("(Host: {}, Port {}: Closed)".format(ip,port))
            # pass
        else:
            if VERBOSE:
                print ("Host: {}, Port {}: Open!".format(ip,port))
            # Try getting ES answer
            # first try http with no authentication
            auth = False
            proto = 'http'
            encr = False
            res = runRequest(proto,hostname,port,'',auth)
            if res['code'] == HTTP_ERROR:
                # now try with https
                proto = 'https'
                encr = True
                res = runRequest(proto,hostname,port,'',auth)
                # if we need auth, try again with auth
            if res['code'] == HTTP_UNAUTHORIZED:
                # auth in place, retry with auth
                auth = True
                res = runRequest(proto,hostname,port,'',auth)
            if res['code'] == HTTP_OK:
                # grab info on the cluster name & version
                esAnswer = res['content']
                clusterName = "null"
                name = "null"
                versionNumber = 'null'
                if 'cluster_name' in esAnswer:
                    clusterName = esAnswer['cluster_name']
                if 'name' in esAnswer:
                    name = esAnswer['name']
                if 'version' in esAnswer:
                    if 'number' in esAnswer['version']:
                        versionNumber = esAnswer['version']['number']
                # then grab stats on node from /_stats/docs,store
                res = runRequest(proto,hostname,port,'/_stats/docs,store',auth)
                if res['code'] == HTTP_OK:
                    esAnswer = res['content']
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
                    print ("==> Found Host: {}, Port: {}, Encrypted: {}, Authenticated: {}, Cluster name: {}, Name: {}, Version: {}, Total number of docs: {}, Total size (MB): {}".format(ip, port, encr, auth, clusterName, name, versionNumber, totalDocs, totalSize))
                    outputTargets['targets'].append({
                            "proto": proto,
                            "host": ip,
                            "port": port,
                            "user": user,
                            "pwd": pwd
                        })
                    logFile.write("{},{},{},{},{},{},{},{},{}\r\n".format(ip, port, encr, auth, clusterName, name, versionNumber, totalDocs, totalSize))
            else:
                print ("==> Found Host: {}, Port {}, Encrypted: {}, Authenticated: {}".format(ip, port, encr, auth))
                logFile.write("{},{},{},{}\r\n".format(ip, port, encr, auth))



# sub function just running the GET
def runRequest(proto,host,port,query,auth):
    res = { 'code': HTTP_ERROR, 'encrypted': True, 'authenticated': True, 'content': ''}
    res['encrypted'] = (proto == 'https')
    res['authenticated'] = auth
    url = proto + '://' + host + ':' + port + '/' + query
    if VERBOSE:
        print ("Calling query {}".format(url))
    if auth:
        # create an authorization handler for basic auth on Elasticsearch
        p = HTTPPasswordMgrWithDefaultRealm()
        p.add_password(None, url, user, pwd)
        auth_handler = HTTPBasicAuthHandler(p)
        opener = build_opener(auth_handler)
        install_opener(opener)
    # add headers
    headers = {}
    headers['User-Agent'] = DEFAULT_UA
    try:
        # run request
        req = Request(url,headers=headers)
        r = urlopen(req)
    except HTTPError as e:
        if VERBOSE:
            print('Error HTTPError: '+str(e))
        if str(e).find('Unauthorized') > 0:
            res['code'] = HTTP_UNAUTHORIZED
        return res
    except URLError as e:
        if VERBOSE:
            print('Error URLError: '+str(e))
        return res
    except Exception as e:
        if VERBOSE:
            print('Error: '+str(e))
        return res
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    else:
        try:
            if r.code == 200:
                content = json.loads(r.read().decode('utf-8'))
                res['code'] = HTTP_OK
                res['content'] = content
                return res
            else:
                return res
        except Exception as e:
            if VERBOSE:
                print('Error: '+str(e))
            return res
        except:
            print("Unexpected error:", sys.exc_info()[0])
            raise

def portRangeToList(portRange):
    result = []
    for part in portRange.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            result.extend(range(start, end + 1))
        else:
            result.append(part)
    return result



# Getting arguments
parser = argparse.ArgumentParser(description='Port scan network to find Elasticsearch clusters running.')
parser.add_argument('-t', action='store', default='', dest='targets', help='IP range (CIDR format, eg 10.50.3.0/24) or simple hostname to scan (default: localhost)')
parser.add_argument('-p', action='store', default='', dest='ports', help='Port range (eg 9200-9210,9300-9310) where Elasticsearch is running (default: 9200)')
parser.add_argument('-u', action='store', default='', dest='user', help='Username to use to authenticate to Elasticsearch (default: elastic)')
parser.add_argument('-pwd', action='store', default='', dest='password', help='Username to use to authenticate to Elasticsearch (default: changeme)')
parser.add_argument('-o', action='store', default='', dest='output', help='Output file in json format (default: targets.json)')
parser.add_argument('--nb-threads', action='store', default='', dest='nbt', help='Number of hosts to scan in parallel (default: 10)')
parser.add_argument('--socket-timeout', action='store', default='', dest='to', help='Seconds to wait for each host/port scanned. Set it to 2 on the Internet, 0.5 in local networks (default: 2)')
parser.add_argument('--log-file', action='store', default='', dest='log', help='Log file with verbose output (default: es-scanner.csv)')
parser.add_argument('--verbose', action='store_true', default=False, help='Turn on verbose output in console')
results = parser.parse_args()
if results.targets != '':
    targets = results.targets
if results.ports != '':
    ports = portRangeToList(results.ports)
if results.user != '':
    user = results.user
if results.password != '':
    pwd = results.password
if results.output != '':
    OUTPUT_FILE = results.output
else:
    OUTPUT_FILE = DEFAULT_OUTPUT_FILE
if results.nbt != '':
    NB_THREADS = results.nbt
else:
    NB_THREADS = DEFAULT_NB_THREADS
if results.to != '':
    TCP_SOCKET_TIMEOUT = results.to
else:
    TCP_SOCKET_TIMEOUT = DEFAULT_TCP_SOCKET_TIMEOUT
if results.log != '':
    LOG_FILE = results.log
else:
    LOG_FILE = DEFAULT_LOG_FILE
VERBOSE = results.verbose


# opening log file
logFile = open(LOG_FILE,"w")
# simple header for csv file
logFile.write("Host,Port,Encrypted,Authenticated,Cluster_name,Name,Version,Total_nb_docs,Total_size_in_MB\r\n")


# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # gets a worker from the queue
        worker = q.get(True,THREAD_TIMEOUT)
        # Run the example job with the avail worker in queue (thread)
        #try:
        portscan(worker)
        # except:
        #     print ("Error in thread...")
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


# start workers for each address (if an IP range)
if targets.find('/') > 0:
    for target in ipaddress.IPv4Network(targets):
        q.put(str(target))
else:
    q.put(str(targets))


# wait until the thread terminates.
q.join()

# write result in output file
if VERBOSE:
    print("Finishing execution. Outputting targets to file...")
    print(outputTargets)
targetsFile = open(OUTPUT_FILE,"w")
# simpler header when inventory only
targetsFile.write(json.dumps(outputTargets, sort_keys=True, indent=4, separators=(',', ': ')))


# close files and leave
logFile.close()
targetsFile.close()
print('')
print("Scan complete in {} seconds!".format(int(time.time() - start_time)))
