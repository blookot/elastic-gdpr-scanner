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
import re
import argparse
import ipaddress

from transformers import AutoModelForCausalLM , AutoTokenizer
import torch


# variables and inputs
VERBOSE = False
SCAN_FIRST_INDEX_ONLY = False
THREAD_TIMEOUT = 240                 # timeout per host, in seconds
TCP_SOCKET_TIMEOUT = 2              # timeout for port scan, in seconds
NB_THREADS = 10             # nb of targets to scan in parallel
UA = 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17'       # user agent used to call elasticsearch
REGEXES_FILE = 'regexes.json'
TARGETS_FILE = 'targets.json'
LOG_FILE = 'es-gdpr-report.csv'
LOG_FILE_FORMAT = 'csv'
LOG_JSON = {"issues": []}
HTTP_OK = 0
HTTP_ERROR = -1
HTTP_UNAUTHORIZED = -2




# Read regexes
regexes = {}
try:
    with open(REGEXES_FILE, 'r') as f:
        regexes = json.load(f)
except FileNotFoundError:
    print(f"The regex file {REGEXES_FILE} does not exist. Exiting...")
    exit(1)



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
def rgpdScan(target):
    proto = target['proto']
    ip = target['host']
    port = target['port']
    user = target['user']
    pwd = target['pwd']
    if VERBOSE:
        print ("** DEBUG ** Scanning Host: {}, Port {}".format(ip,port))
    res = runRequest(proto,ip,port,user,pwd,'')
    if res['code'] != HTTP_OK:
        print("Couldn't query index list!")
    else:
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

        # then explore indices
        res = runRequest(proto,ip,port,user,pwd,'_stats/docs,store')
        esAnswer = res['content']
        # /_cat/indices introduced in 1.3, not working on v0.90 (thus relying on node stats...)
        if 'indices' in esAnswer:
            for index, indexDetails in iter(esAnswer['indices'].items()):
                # consider non-internal indices
                if index[:1] != '.':
                    if VERBOSE:
                        print ("** Testing index {}".format(index))
                    # grab index stats
                    # print (json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))
                    indexNbDocs = indexDetails['total']['docs']['count']
                    indexSize = int(int(indexDetails['total']['store']['size_in_bytes'])/(1024*1024))
                    # then get first doc : /[index]/_search?size=1
                    res = runRequest(proto,ip,port,user,pwd,index+"/_search?size=1")
                    if res['code'] == HTTP_OK:
                        esDocs = res['content']
                        # check if at least 1 document
                        if esDocs['hits']['total'] == 0:
                            if VERBOSE:
                                print ("No document found in index "+index)
                            # logFile.write("{},{},{},{},{},{},{},{},N/A (no doc)\r\n".format(ip, port, clusterName, name, versionNumber, index, indexNbDocs, indexSize))
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
                                    print ('** Testing index {} with regexes, result: {}'.format(index, rgpdCheck['result']))
                                if rgpdCheck['result']:
                                    for m in rgpdCheck['matches']:
                                        # display uncompliant indices even if not verbose
                                        print ("** Host: {}, Port: {}, Cluster name: {}, Name: {}, Version: {} - Index {} not compliant! (value '{}' matched regex '{}')".format(ip, port, clusterName, name, versionNumber, index, m['value'], m['regex']))
                                        if LOG_FILE_FORMAT == 'csv':
                                            logFile.write("{},{},{},{},{},{},{},{},{},{}\r\n".format(ip, port, clusterName, name, versionNumber, index, indexNbDocs, indexSize, m['value'], m['regex']))
                                        else:
                                            LOG_JSON['issues'].append({
                                                    "ip": ip,
                                                    "port": port,
                                                    "clusterName": clusterName,
                                                    "name": name,
                                                    "versionNumber": versionNumber,
                                                    "index": index,
                                                    "indexNbDocs": indexNbDocs,
                                                    "indexSize": indexSize,
                                                    "fieldValue": m['value'],
                                                    "regex": m['regex']
                                                })
                                nerCheck = ner_checker(source)
                                if VERBOSE:
                                    print ('** Testing index {} with NER, result: {}'.format(index, nerCheck['result']))
                                if nerCheck['result']:
                                    for m in nerCheck['matches']:
                                        # display uncompliant indices even if not verbose
                                        print ("** Host: {}, Port: {}, Cluster name: {}, Name: {}, Version: {} - Index {} not compliant! (value '{}' matched NER class '{}')".format(ip, port, clusterName, name, versionNumber, index, m['value'], m['class']))
                                        if LOG_FILE_FORMAT == 'csv':
                                            logFile.write("{},{},{},{},{},{},{},{},{},{}\r\n".format(ip, port, clusterName, name, versionNumber, index, indexNbDocs, indexSize, m['value'], m['class']))
                                        else:
                                            LOG_JSON['issues'].append({
                                                    "ip": ip,
                                                    "port": port,
                                                    "clusterName": clusterName,
                                                    "name": name,
                                                    "versionNumber": versionNumber,
                                                    "index": index,
                                                    "indexNbDocs": indexNbDocs,
                                                    "indexSize": indexSize,
                                                    "fieldValue": m['value'],
                                                    "nerClass": m['class']
                                                })
                    # scan only first index to go faster
                    if SCAN_FIRST_INDEX_ONLY:
                        break
        # indices listing didn't work
        else:
            print ('Couldn\'t list indices')


# regex checker func (outputs true when regex match, ie outputs true when *not* compliant)
def regex_checker(jsonDoc):
    # print ('Testing: '+json.dumps(jsonDoc))
    output = {"result":False, "matches": []}
    for key, value in iter(jsonDoc.items()):
        if isinstance(value, str):
            for r in regexes['regexes']:
                if r['executed']:
                    if VERBOSE:
                        print ('\tCheck '+value+' against regex \''+r['regex']+'\': '+str(check))
                    check = bool(re.search(r['regex'], value))
                    if check:
                        output['result'] = True
                        output['matches'].append({"value":value, "regex":r['regex']})
        elif isinstance(value,dict):
            output['matches'].append(regex_checker(value)['matches'])
    return output


# NER checker, returns <class>: [array of strings where entity was found]
def ner_checker(jsonDoc):
    output = {"result":False, "matches": []}
    new_prompt = prompt.format(classes="\n".join(classes_list) , text=jsonDoc)
    tokenized_input = tokenizer(new_prompt , return_tensors="pt").to(device)
    modelOutput = model.generate(**tokenized_input , max_new_tokens=6000)
    pii_classes = tokenizer.decode(modelOutput[0] , skip_special_tokens=True).split("The PII data are:\n")[1]
    if pii_classes != 'NO PII DATA PRESENT':
        for l in iter(pii_classes.splitlines()):
            (c,v) = l.split(' : ')
            output['result'] = True
            output['matches'].append({"value":v, "class":c})
    return output


# sub function just running the GET
def runRequest(proto,host,port,user,pwd,query):
    res = { 'code': HTTP_ERROR, 'encrypted': True, 'authenticated': True, 'content': ''}
    url = proto + '://' + host + ':' + port + '/' + query
    if VERBOSE:
        print ("Calling query {}".format(url))
    # create an authorization handler for basic auth on Elasticsearch
    p = HTTPPasswordMgrWithDefaultRealm()
    p.add_password(None, url, user, pwd)
    auth_handler = HTTPBasicAuthHandler(p)
    opener = build_opener(auth_handler)
    install_opener(opener)
    # add headers
    headers = {}
    headers['User-Agent'] = UA
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



# Getting arguments
parser = argparse.ArgumentParser(description='Scan Elasticsearch clusters to check for GDPR compliance.')
parser.add_argument('-t', action='store', default='', dest='targets', help='Target file (sample target file: targets-example.json) to read targets from (default: targets.json)')
parser.add_argument('-r', action='store', default='', dest='regex', help='Specific regex to look for (if set, cancels running all regexes from regexes.json file)')
parser.add_argument('-o', action='store', default='', dest='output', help='Name of the file to output results. csv or json supported (default: es-gdpr-report.csv)')
parser.add_argument('--nb-threads', action='store', default='', dest='nbt', help='Number of hosts to scan in parallel (default: 10)')
parser.add_argument('--socket-timeout', action='store', default='', dest='to', help='Seconds to wait for each host/port scanned. Set it to 2 on the Internet, 0.5 in local networks (default: 2)')
parser.add_argument('--verbose', action='store_true', default=False, help='Turn on verbose output in console')
results = parser.parse_args()
if results.targets != '':
    TARGETS_FILE = results.targets
if results.regex != '':
    regexes = {
        "regexes": [{
            "desc": "Custom regex (user input)",
            "family": "Custom",
            "executed": True,
            "regex": results.regex
        }]
    }
if results.output != '':
    LOG_FILE = results.output
    if LOG_FILE[-4:] == 'json':
        LOG_FILE_FORMAT = 'json'
if results.nbt != '':
    NB_THREADS = results.nbt
if results.to != '':
    TCP_SOCKET_TIMEOUT = results.to
VERBOSE = results.verbose


# Read targets from file
targets = {}
try:
    with open(TARGETS_FILE, 'r') as f:
        targets = json.load(f)
except FileNotFoundError:
    print(f"The targets file {TARGETS_FILE} does not exist. Exiting...")
    exit(1)

# prepare log file
logFile = open(LOG_FILE,"w")
if LOG_FILE_FORMAT == 'csv':
    # write header
    logFile.write("Host,Port,Cluster_name,Name,Version,Index,Index_nb_docs,Index_size_in_MB,Value,Regex\r\n")

# initialize NER
device = "cuda" if torch.cuda.is_available() else "cpu"
model = AutoModelForCausalLM.from_pretrained("betterdataai/PII_DETECTION_MODEL").to(device)
tokenizer = AutoTokenizer.from_pretrained("betterdataai/PII_DETECTION_MODEL")
# Select detection classes to be used
classes_list = ['<pin>','<api_key>','<bank_routing_number>','<bban>','<company>','<credit_card_number>','<credit_card_security_code>','<customer_id>','<date>','<date_of_birth>','<date_time>','<driver_license_number>','<email>','<employee_id>','<first_name>','<iban>','<ipv4>','<ipv6>','<last_name>','<local_latlng>','<name>','<passport_number>','<password>','<phone_number>','<social_security_number>','<street_address>','<swift_bic_code>','<time>','<user_name>']
# NER prompt
prompt = """You are an AI assistant who is responisble for identifying Personal Identifiable information (PII). You will be given a passage of text and you have to \
identify the PII data present in the passage. You should only identify the data based on the classes provided and not make up any class on your own.

```PII Classes```
{classes}

The given text is:
{text}

The PII data are:
"""


# The threader thread pulls a worker from the queue and processes it
def threader():
    while True:
        # gets a worker from the queue
        worker = q.get(True,THREAD_TIMEOUT)
        # Run the example job with the avail worker in queue (thread)
        # try:
        rgpdScan(worker)
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


# start workers for each target
for t in targets['targets']:
    q.put(t)

# wait until the thread terminates.
q.join()


# write result in output file
if LOG_FILE_FORMAT == 'json':
    logFile.write(json.dumps(LOG_JSON, sort_keys=True, indent=4, separators=(',', ': ')))

# close & end
logFile.close()
print('')
print("Scan complete in {} seconds!".format(int(time.time() - start_time)))
