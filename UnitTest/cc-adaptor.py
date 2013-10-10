#!/usr/bin/env python


# Software License Agreement (BSD License)
#
# Copyright (c) 2009, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: Tony Lee tony.li@sinobot.com.cn


import sys
import getopt, sys, os, stat
os.chdir('/usr/sbin')
sys.path.append('./gen-py')
from NCInfo import NCInfoServlet
from NCInfo.ttypes import *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
import gzip
import Queue
import thread
import threading
import time
import datetime
import tarfile
import gzip
import logging
import string, StringIO
import ldap
from xml.dom.minidom import Document
from xml.dom import minidom
from hashlib import sha1 as sha
#from M2Crypto import BN, EVP, RSA, util, Rand, m2, X509
from binascii import hexlify, unhexlify
from subprocess import *
import platform
import urllib
import re
import shutil
from amqplib import client_0_8 as amqp

BASE_DN = 'cn=clc,o=cloudbot,o=sinobot'
SEARCH_FILTER = 'ou=prefrencePrompt'
INTERVAL_KEY = 'delayTime'
TIMEOUT_KEY = 'AdaptInstanceTimeout'
AMQP_KEY = 'MaqpServerIp'
DEFAULT_INTERVAL = 20
DEFAULT_TIMEOUT =3600

LOG_PATH     = os.path.expandvars('$HOME') + '/luhya/logs'
LOG_FILENAME = LOG_PATH+'/paas_cc_adaptor.log'
LOG_ERROR    = 7
LOG_INFO     = 6
if not os.path.exists(LOG_PATH):
    os.makedirs(LOG_PATH)
logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)


#convert eucalypt data to python format
#c code:
#typedef enum instance_states_t {
NO_STATE = 0
RUNNING = 1
BLOCKED = 2
PAUSED = 3
SHUTDOWN = 4
SHUTOFF = 5
CRASHED = 6
STAGING = 7
BOOTING = 8
CANCELED = 9
PENDING = 10
EXTANT = 11 
TEARDOWN = 12
TOTAL_STATES = 13
#} instance_states

SYSTEMUSEDMEM = 256 #estimated node system sued memery

switch = threading.Lock()  # pthread mutex                                                          
instances = {'error':{'error':'error'},'error':{'error':'error'}}  # just for fit thrift rule
resources = {'error':{'error':'error'},'error':{'error':'error'}}  # just for fit thrift rule

#paas log function
def paas_log(logstring,level):
    "paas log function"
    if(level == LOG_ERROR):
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS ERROR:'
        logstr = logstr + timestr + logstring
        logging.error(logstr)
    else:
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS INFO:'
        logstr = logstr + timestr + logstring
        logging.info(logstr)
    return 0  


# get ldap info from the configure file
def get_ldap_info():
    "get_ldap_info"
    fh = os.popen ('cat /etc/eucalyptus/eucalyptus-ldap.conf')
    setconfig = 1
    for ln in fh.readlines ():
        if 'LDAP_URI' in ln:
            ln = ln.strip (' \n')
            ls = ln.rsplit('"')
            ldap_uri = ls[1]
            setconfig = 0
        if 'LDAP_USER' in ln:
            ln = ln.strip (' \n')
            ls = ln.rsplit('"')
            user_name = ls[1]
        if 'LDAP_PASSWORD' in ln:
            ln = ln.strip (' \n')
            ls = ln.rsplit('"')
            password = ls[1]
    if(setconfig):
        return None
    return ldap_uri,user_name,password


# login to ldap server
def login_ldap(ldap_uri,user_name, password): 
    "login_ldap" 
    try:  
        Server = ldap_uri   
        Scope = ldap.SCOPE_SUBTREE   
        ln = ldap.initialize(Server)  
        ln.set_option(ldap.OPT_REFERRALS, 0) 
        ln.protocol_version = 3  
        ln.simple_bind_s(user_name, password) 
        return ln 
    except ldap.LDAPError, e:  
        print e  
        return None  

# Get the interval time from ldap server
def get_interval_time(ldap_uri,user_name,password,baseDN,searchFilter,key):
    "get_interval_time"
    ncldap = login_ldap(ldap_uri,user_name, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None 
    interval = None
    try:
        ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        result_set = []
	while (1):
		result_type, result_data = ncldap.result(ldap_result_id, 0)
		if (result_data == []):
			break
		else:
                    result_set.append(result_data)
        for l in result_set:
                for ll in l:
                    lll = ll[1]
                    if lll.has_key(key):
                        intval = lll.get(key)
                        intval =  intval[0]    
                        interval = int(intval) 
                        break                  
    except ldap.LDAPError, e:
	print e
        return -1  
    return interval

# Get the timeout time from ldap server
def get_timeout_time(ldap_uri,user_name,password,baseDN,searchFilter,key):
    "get_timeout_time"
    ncldap = login_ldap(ldap_uri,user_name, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None 
    timeout = None
    try:
        ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        result_set = []
	while (1):
		result_type, result_data = ncldap.result(ldap_result_id, 0)
		if (result_data == []):
			break
		else:
                    result_set.append(result_data)
        for l in result_set:
                for ll in l:
                    lll = ll[1]
                    if lll.has_key(key):
                        intval = lll.get(key)
                        intval =  intval[0]    
                        timeout = int(intval) 
                        break                  
    except ldap.LDAPError, e:
	print e
        return -1  
    return timeout

# Get RabbitMQ server ip from ldap server
def get_rabbitmq_ip(ldap_uri,user_name,password,baseDN,searchFilter,key):
    "get_rabbitmq_ip"
    ncldap = login_ldap(ldap_uri,user_name, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None 
    amqpip = None
    try:
        ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
        result_set = []
	while True:
		result_type, result_data = ncldap.result(ldap_result_id, 0)
		if (result_data == []):
			break
		else:
                    result_set.append(result_data)
        for l in result_set:
                for ll in l:
                    lll = ll[1]
                    if lll.has_key(key):
                        pairip = lll.get(key)
                        amqpip =  pairip[0]    
                        break                  
    except ldap.LDAPError, e:
	print e
        return None 
    return amqpip

#clean up the timeout instances infomation
def clean_up_timeout():
    "clean_up_timeout"
    ldap_uri,user_name,password = get_ldap_info()
    timeout = get_timeout_time(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,TIMEOUT_KEY)
    if(timeout < 0):
        timeout = DEFAULT_TIMEOUT
    for ipkey in instances:
        if(ipkey == 'error'):
            pass
        else:
            for instnaceid in instances[ipkey]:
                recenttime = instances[ipkey][instnaceid]['updateTime'] 
                if((now - recenttime) > timeout):
                    del instances[ipkey][instnaceid] 
                    log_string = 'instance clean up nc:%s,instance:%s' % (ipkey,instnaceid)
                    paas_log(log_string,LOG_INFO) 
    return 0 

def isNum(value):
    try:
        value + 1
    except TypeError:
        return False
    else:
        return True

# display all instances infomation
def display_instances():
    "display_instances"
    print '  '
    print '  '
    print '  '
    print '--display_instances-- '
    for ip in instances:
        if(ip == 'error'):
            pass
        else:
            nc = instances[ip]
            for id in nc:
                instance = nc[id]
                print instance
    print '--display_instances-- '
    print '  '
    print '  '
    print '  '
    return 0


#set RabbitMQ rule, queue ,binding info
def set_amqp(host):
    "set_amqp"
    if(host == None):
        host="localhost:5672"        
    conn = amqp.Connection(host, userid="guest", password="guest", virtual_host="/", insist=False)
    chan = conn.channel()
    chan.queue_declare(queue="nc_raws", durable=True, exclusive=False, auto_delete=False)
    chan.exchange_declare(exchange="sorting_room", type="direct", durable=True, auto_delete=False,)
    chan.queue_bind(queue="nc_raws", exchange="sorting_room", routing_key="jason")
    paas_log('set_ampq ok',LOG_INFO)
    return chan

# thirft handler class 
class NCInfoServletHandler:
    def __init__(self):
        self.log = {}

    # thrift handler senderResource, the function name can not be changed.
    def senderResource(self, url):
        "senderResource"
        print 'senderResource(%s)' % (url)
        log_string = 'senderResource(%s)' % (url)
        paas_log(log_string,LOG_INFO)
        switch.acquire()
        nodeMemUsed = 0
        cores = 0
        if(instances.has_key(url)):
            node = instances[url]
            for instanceid in node:
                instance = node[instanceid]
                deleteflag = instance['deleteflag']
                if(deleteflag):
                    pass
                else:
                    if(instance.has_key('params_original')):
                        nodeMemUsed = nodeMemUsed + instance['params_original']['memorySize']
                        cores = cores + instance['params_original']['numberOfCores']               
        resource_info = {}
        findre = 0
        for rekey in resources:
            if(rekey == url):
                resource_info = resources[url]
                findre = 1
        if(findre):
            memorySizeTotal = int(resource_info['memorySizeMax'])/1024 - SYSTEMUSEDMEM
            if(nodeMemUsed < 0):
                nodeMemUsed = 0
            memorySizeAvail = memorySizeTotal - nodeMemUsed
            if(memorySizeAvail < 0):
                memorySizeAvail = 0
            if(cores < 0):
                cores = 0
            CoresAvailable=int(resource_info['numberOfCoresMax'])-cores           
            info = ResourceInfo(nodeStatus=resource_info['nodeStatus'], memorySizeMax=memorySizeTotal, memorySizeAvailable=memorySizeAvail,diskSizeMax=resource_info['diskSizeMax']/1024, diskSizeAvailable=resource_info['diskSizeAvailable']/1024,numberOfCoresMax=int(resource_info['numberOfCoresMax']), numberOfCoresAvailable=CoresAvailable, publicSubnets=resource_info['publicSubnets'])
        else:
            info = ResourceInfo()
            log_string = 'senderResource:nc not find (%s)' % (url)
            paas_log(log_string,LOG_INFO)
        switch.release()
        print info
        return info

    # thrift handler senderInstance, the function name can not be changed.    
    def senderInstance(self, url):
        "senderInstance"
        print 'senderInstance(%s)' % (url)
        log_string = 'senderInstance(%s)' % (url)
        paas_log(log_string,LOG_INFO)
        switch.acquire()
        now = time.time()
        now = int(now)
        ldap_uri,user_name,password = get_ldap_info()
        interval = get_interval_time(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,INTERVAL_KEY)
        if(interval < 0):
            interval = DEFAULT_INTERVAL
        interval = interval + 10
        findin = 0
        if(instances.has_key(url)):
            findin = 1
        list_info = []
        if(findin):
            instances_detail = instances.get(url)
            for key in instances_detail:   
                instance_info = instances_detail.get(key)
                updatetime = instance_info['updateTime']
                gaptime = now - updatetime
                if(gaptime < interval):
                    ncgroupNames = ['error', 'error', 'error','error', 'error']
                    nCInstParams = NCInstParams(memorySize = instance_info['params']['memorySize'], diskSize =instance_info['params']['diskSize'] , numberOfCores = instance_info['params']['numberOfCores'] )
                    nCNetConf = NCNetConf(vlan = instance_info['ncnet']['vlan'], publicMac = instance_info['ncnet']['publicMac'], privateMac = instance_info['ncnet']['privateMac'], publicIp = instance_info['ncnet']['publicIp'], privateIp = instance_info['ncnet']['privateIp'])
                    ncSpiceInfo =  NCSpiceInfo(hostIp = 'error', port = 0, passwd = 'error' )
                    ncVolume1 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                    ncVolume2 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                    ncVolume = [ncVolume1,ncVolume2]
                    instance_imageid = instance_info['imageId'];
                    try:
                        info = InstanceInfo(instanceId=instance_info['instanceId'], imageId=instance_imageid, imageURL=instance_info['imageURL'], kernelId=instance_info['kernelId'],kernelURL=instance_info['kernelURL'], ramdiskId=instance_info['ramdiskId'],ramdiskURL=instance_info['ramdiskURL'], reservationId=instance_info['reservationId'],userId=instance_info['userId'], retries=instance_info['retries'], stateName=instance_info['stateName'], stateCode=instance_info['stateCode'], state=instance_info['state'], keyName=instance_info['keyName'], privateDnsName=instance_info['privateDnsName'], dnsName=instance_info['dnsName'], launchTime=instance_info['launchTime'], terminationTime=instance_info['terminationTime'], params=nCInstParams, ncnet=nCNetConf,userData=instance_info['userData'], launchIndex=instance_info['launchIndex'], groupNames=ncgroupNames, groupNamesSize=instance_info['groupNamesSize'],volumes=ncVolume, volumesSize=instance_info['volumesSize'], ncspiceinfo=ncSpiceInfo, bundle=instance_info['bundle'])                   
                        list_info.append(info)
                    except e:
                        log_string = 'InstanceInfo error'
                        paas_log(log_string,LOG_ERROR)
                        print e
        switch.release()
        return list_info

    # thrift handler sendToAdapt, the function name can not be changed. 
    def sendToAdapt(self, instanceInfo):
        "sendToAdapt"
        print 'sendToAdapt(%s)' % (instanceInfo.instanceId)
        print 'sendToAdapt(%s)' % (instanceInfo.targetNode)
        log_string = 'sendToAdapt:%s' % (str(instanceInfo))
        paas_log(log_string,LOG_INFO)
        ip = instanceInfo.targetNode
        instance_id = instanceInfo.instanceId
        switch.acquire()
        now = time.time()
        now = int(now)
        if(instances.has_key(ip)):
            instances_info = instances[ip]
            if (instances_info.has_key(instance_id)):
                instances[ip][instance_id]['imageId'] = instanceInfo.imageId
                instances[ip][instance_id]['imageURL'] = instanceInfo.imageURL
                instances[ip][instance_id]['kernelId'] = instanceInfo.kernelId
                instances[ip][instance_id]['kernelURL'] = instanceInfo.kernelURL
                instances[ip][instance_id]['ramdiskId'] = instanceInfo.ramdiskId
                instances[ip][instance_id]['ramdiskURL'] = instanceInfo.ramdiskURL
                instances[ip][instance_id]['reservationId'] = instanceInfo.reservationId
                instances[ip][instance_id]['userId'] = instanceInfo.userId
                instances[ip][instance_id]['stateName'] = 'Pending'
                instances[ip][instance_id]['stateCode'] = PENDING
                instances[ip][instance_id]['deleteflag'] = 0
                instances[ip][instance_id]['updateTime'] = now
                instances[ip][instance_id]['keyName'] = instanceInfo.keyName
                CCParams = instanceInfo.params
                NCInstParams = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
                instances[ip][instance_id]['params'] = NCInstParams
                NCInstParams_original = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
                instances[ip][instance_id]['params_original'] = NCInstParams_original
                CCNetConf = instanceInfo.ncnet
                NCNetConf = {'vlan':CCNetConf.vlan, 'publicMac':CCNetConf.publicMac, 'privateMac':CCNetConf.privateMac, 'publicIp':CCNetConf.publicIp, 'privateIp':CCNetConf.privateIp}
                instances[ip][instance_id]['ncnet'] = NCNetConf
                instances[ip][instance_id]['userData'] = instanceInfo.userData
                instances[ip][instance_id]['launchIndex'] = instanceInfo.launchIndex
            else:
                instance_new = {}
                instance_new['instanceId'] = instanceInfo.instanceId
                instance_new['imageId'] = instanceInfo.imageId
                instance_new['imageURL'] = instanceInfo.imageURL
                instance_new['kernelId'] = instanceInfo.kernelId
                instance_new['kernelURL'] = instanceInfo.kernelURL
                instance_new['ramdiskId'] = instanceInfo.ramdiskId
                instance_new['ramdiskURL'] = instanceInfo.ramdiskURL
                instance_new['reservationId'] = instanceInfo.reservationId
                instance_new['userId'] = ''
                instance_new['retries'] = 0
                instance_new['stateName'] = 'Pending'
                instance_new['stateCode'] = PENDING
                instance_new['deleteflag'] = 0
                instance_new['updateTime'] = now
                instance_new['state'] = 0
                instance_new['keyName'] = instanceInfo.keyName
                instance_new['privateDnsName'] = ''
                instance_new['dnsName'] = ''
                instance_new['launchTime'] = 0   
                instance_new['terminationTime'] = 0
                CCParams = instanceInfo.params
                NCInstParams = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
                instance_new['params'] = NCInstParams
                NCInstParams_original = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
                instance_new['params_original'] = NCInstParams_original
                CCNetConf = instanceInfo.ncnet
                NCNetConf = {'vlan':CCNetConf.vlan, 'publicMac':CCNetConf.publicMac, 'privateMac':CCNetConf.privateMac, 'publicIp':CCNetConf.publicIp, 'privateIp':CCNetConf.privateIp}
                instance_new['ncnet'] = NCNetConf
                instance_new['userData'] = instanceInfo.userData
                instance_new['launchIndex'] = instanceInfo.launchIndex
                ncgroupNames = ['Do', 'not', 'use','this', 'info']
                instance_new['groupNames'] = ncgroupNames
                instance_new['groupNamesSize'] = 0
                ncVolume1 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                ncVolume2 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                ncVolume = [ncVolume1,ncVolume2]
                instance_new['volumes'] = ncVolume 
                instance_new['volumesSize'] = 0 
                ncSpiceInfo =  NCSpiceInfo(hostIp = 'error', port = 0, passwd = 'error' )
                instance_new['ncspiceinfo'] = ncSpiceInfo
                instance_new['bundle'] = 0  
                instances[ip][instance_id] = instance_new             
        else:
            instances_detail = {}
            instance_new = {}
            instance_new['instanceId'] = instanceInfo.instanceId
            instance_new['imageId'] = instanceInfo.imageId
            instance_new['imageURL'] = instanceInfo.imageURL
            instance_new['kernelId'] = instanceInfo.kernelId
            instance_new['kernelURL'] = instanceInfo.kernelURL
            instance_new['ramdiskId'] = instanceInfo.ramdiskId
            instance_new['ramdiskURL'] = instanceInfo.ramdiskURL
            instance_new['reservationId'] = instanceInfo.reservationId
            instance_new['userId'] = ''
            instance_new['retries'] = 0
            instance_new['stateName'] = 'Pending'
            instance_new['stateCode'] = PENDING
            instance_new['deleteflag'] = 0
            instance_new['updateTime'] = now
            instance_new['state'] = 0
            instance_new['keyName'] = instanceInfo.keyName
            instance_new['privateDnsName'] = ''
            instance_new['dnsName'] = ''
            instance_new['launchTime'] = 0   
            instance_new['terminationTime'] = 0
            CCParams = instanceInfo.params
            NCInstParams = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
            instance_new['params'] = NCInstParams
            NCInstParams_original = {'memorySize':CCParams.memorySize,'diskSize':CCParams.diskSize,'numberOfCores':CCParams.numberOfCores}
            instance_new['params_original'] = NCInstParams_original
            CCNetConf = instanceInfo.ncnet
            NCNetConf = {'vlan':CCNetConf.vlan, 'publicMac':CCNetConf.publicMac, 'privateMac':CCNetConf.privateMac, 'publicIp':CCNetConf.publicIp, 'privateIp':CCNetConf.privateIp}
            instance_new['ncnet'] = NCNetConf
            instance_new['userData'] = instanceInfo.userData
            instance_new['launchIndex'] = instanceInfo.launchIndex
            ncgroupNames = ['Do', 'not', 'use','this', 'info']
            instance_new['groupNames'] = ncgroupNames
            instance_new['groupNamesSize'] = 0
            ncVolume1 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'error')
            ncVolume2 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'error')
            ncVolume = [ncVolume1,ncVolume2]
            instance_new['volumes'] = ncVolume 
            instance_new['volumesSize'] = 0 
            ncSpiceInfo =  NCSpiceInfo(hostIp = 'error', port = 0, passwd = 'error' )
            instance_new['ncspiceinfo'] = ncSpiceInfo
            instance_new['bundle'] = 0  
            instances_detail[instance_id] = instance_new
            instances[ip] = instances_detail
        switch.release()        
        return 'receive OK!'

    def deleteInstance(self,instanceId,url):
        "deleteInstance"
        print 'deleteInstance(%s)' % (instanceId)
        print 'deleteInstance(%s)' % (url)
        log_string = 'get deleteInstance command instanceid:%s url:%s' % (instanceId,url)
        paas_log(log_string,LOG_INFO)
        switch.acquire()
        if(instances.has_key(url)):
            if(instances[url].has_key(instanceId)):
                instances[url][instanceId]['stateName'] = 'Teardown'
                instances[url][instanceId]['stateCode'] = TEARDOWN 
                instances[url][instanceId]['deleteflag'] = 1
                log_string = 'set status to teardown instanceid:%s url:%s' % (instanceId,url)
                paas_log(log_string,LOG_INFO)
            else:
                new_instance = {}
                new_instance['stateName'] = 'Teardown'
                new_instance['stateCode'] = TEARDOWN 
                new_instance['deleteflag'] = 1
                instances[url][instanceId] = new_instance
                log_string = 'set status to teardown instanceid:%s url:%s' % (instanceId,url)
                paas_log(log_string,LOG_INFO)
        switch.release()                    
        return 'receive OK!'

# listen from cc and reponse to cc
class listen_cc(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        handler = NCInfoServletHandler()
        processor = NCInfoServlet.Processor(handler)
        transport = TSocket.TServerSocket('localhost',9090)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
        # You could do one of these for a multithreaded server
        #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        #server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)  
        log_string = 'cc-adaptor pthread:listen_cc starting'
        paas_log(log_string,LOG_INFO)
        server.serve()
        log_string = 'cc-adaptor pthread:listen_cc done'
        paas_log(log_string,LOG_INFO)     
                
# define RabbitMQ callback function,
# the main job is done here
def recv_callback(msg):
    "recv_callback"
    for key, val in msg.properties.items():
        aphd = 'application_headers'
        if 'application_headers' in key:
            nc_raw = val
            print nc_raw
            log_string = 'cc-adaptor received from nc:%s' % (str(nc_raw))
            paas_log(log_string,LOG_INFO)
            nc_ip = nc_raw['ip']
            resource_info = nc_raw['resource']
            instances_info = nc_raw['instances']
            now = time.time()
            now = int(now)  
            switch.acquire()
            if(instances.has_key(nc_ip)):
                instances_nc = instances[nc_ip]
                for nkey in instances_info:
                    rl = instances_info[nkey]
                    instanceid = rl['instanceId']
                    find = 1
                    for lgkey in instances_nc:
                        if(lgkey == instanceid):
                            delflag = 1
                            original_delflag = instances[nc_ip][lgkey]['deleteflag']
                            if(original_delflag):
                                delflag = 0
                            else:
                                pass                                                          
                            if(delflag):
                                instances[nc_ip][lgkey]['retries'] = rl['retries']
                                instances[nc_ip][lgkey]['stateName'] = rl['stateName']
                                instances[nc_ip][lgkey]['stateCode'] = rl['stateCode']
                                instances[nc_ip][lgkey]['state'] = rl['state']
                                instances[nc_ip][lgkey]['updateTime'] = now
                                instances[nc_ip][lgkey]['launchTime'] = rl['launchTime'] 
                                NCInstParams = rl['params']
                                instances[nc_ip][lgkey]['params']['memorySize'] = NCInstParams['memorySize']
                                instances[nc_ip][lgkey]['params']['numberOfCores'] = NCInstParams['numberOfCores']
                                NCNetConf = rl['ncnet']
                                instances[nc_ip][lgkey]['ncnet']['publicIp'] = NCNetConf['publicIp']
                                instances[nc_ip][lgkey]['ncnet']['privateIp'] = NCNetConf['privateIp']                        
                            find = 0
                            break
                    if(find):
                        rl['updateTime'] = now
                        rl['deleteflag'] = 0 
                        instances[nc_ip][instanceid] = rl
            else:
                for id in instances_info:
                    instances_info[id]['updateTime'] = now
                    instances_info[id]['deleteflag'] = 0                  
                instances[nc_ip] =  instances_info
            resources[nc_ip] =  resource_info
            try:
                clean_up_timeout()
            except:
                paas_log('clean_up_timeout',LOG_ERROR)            
            switch.release() 

# main thread for pre_init
class main_thread(threading.Thread):
    "main_hread"
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        "main thread interface"
        log_string = 'cc-adaptor main starting'
        paas_log(log_string,LOG_INFO)
        ldap_uri,user_name,password = get_ldap_info()
        log_string = 'get_ldap_info:ldap_uri/%s,user_name/%s' % (ldap_uri,user_name)
        paas_log(log_string,LOG_INFO)
        amqpip = get_rabbitmq_ip(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,AMQP_KEY)
        if (amqpip):
            RabbitMQ_server = amqpip
        else:
            log_string = 'get_rabbitmq_ip error'
            paas_log(log_string,LOG_ERROR)
            sys.exit()
        RabbitMQ_port = 5672
        host = '%s:%d' % (RabbitMQ_server,RabbitMQ_port)
        conn = amqp.Connection(host, userid="guest", password="guest", virtual_host="/", insist=False) 
        chan = conn.channel()
        chan.queue_declare(queue="nc_raws", durable=True, exclusive=False, auto_delete=False)
        chan.exchange_declare(exchange="sorting_room", type="direct", durable=True, auto_delete=False,)
        chan.queue_bind(queue="nc_raws", exchange="sorting_room", routing_key="jason")
        paas_log('queue_bind ok',LOG_INFO)   
     
        #start thread to listen CC
        lstcc = listen_cc()
        lstcc.setDaemon(True)
        lstcc.start() 
        chan.basic_consume(queue='nc_raws', no_ack=True, callback=recv_callback, consumer_tag="testtag")
        while True:
            chan.wait()
        chan.basic_cancel("testtag")
        chan.close()
        conn.close()
          
# the cc-adaptor interface
def pre_init (user_data):
    "normal main interface"
    print "pre_init starting..."
    monitor_thread =  main_thread()
    monitor_thread.start()
    log_string = 'main thread starting and pre_init return'
    paas_log(log_string,LOG_INFO) 
    return 0     
 
def post_init (user_data):
  pass

# for testing or isolated operation purpose
def main():
    "main interface"
    print "cc-adaptor starting..."
    user_data = ''
    pre_init(user_data)
    return 0 #sys.exit()

if __name__ == '__main__':
    main()

