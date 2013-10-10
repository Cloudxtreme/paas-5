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

__all__ = [ 'preInit' , 'postInit']

import sys
sys.path.append("/usr/lib/python2.6/site-packages")
import getopt, sys, os, stat
import cloudbot.utils
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
import socket
import struct
import string, StringIO
import ldap
from xml.dom.minidom import Document
from xml.dom import minidom
from hashlib import sha1 as sha
from binascii import hexlify, unhexlify
from subprocess import *
from types import *
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
RESCUE_ROOT_PATH = os.path.expanduser('~') + '/luhya/CCAdaptorRescue'                # cc-adaptor rescue file root

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

BLANCK_SPACES = '          '

SYSTEMUSEDMEM = 256 #estimated node system sued memery

switch = threading.Lock()  # pthread mutex                                                          
instances = {'error':{'error':'error'},'error':{'error':'error'}}  # just for fit thrift rule
resources = {'error':{'error':'error'},'error':{'error':'error'}}  # just for fit thrift rule

LOG_PATH_ROOT     = os.path.expanduser('~') + '/.luhya/logs'        # log file root
LOG_FILENAME_ERROR = LOG_PATH_ROOT+'/paas_ccadaptor_error.log'     # log error file name
LOG_FILENAME_INFO = LOG_PATH_ROOT+'/paas_ccadaptor_info.log'       # log info file name
MAX_LOGFILE_SIZE = 100*1024*1024L                                  # 100M max lof file size
LOG_ERROR    = 7
LOG_INFO     = 6

# log mutex 
log_mutex = threading.Lock() 

# check paas log file states,if the logf ile is too big then back up the current log file and create new one;
# if there is also a old backup log file, delete it before back up the current log file.
# input: log file name
# output: 0:OK -1:error occur 
def ensure_log_file(logfilepath):
    "ensure_log_file"
    if not os.path.exists(LOG_PATH_ROOT):
        try:
            os.makedirs(LOG_PATH_ROOT)
        except:
            print 'Create log root error!'
            return -1
        return 0
    if not os.path.exists(logfilepath):
        return 0
    if (os.path.getsize(logfilepath) > MAX_LOGFILE_SIZE):
        backfilename = '%s.%d' % (logfilepath,1)
        log_mutex.acquire()
        try:
            if os.path.exists(backfilename):
                os.remove(backfilename)
            os.rename(logfilepath,backfilename)
        except:
            print 'ensure lof file error: %s' % logfilepath
            return -1
        log_mutex.release()
    return 0

# paas log function
# input logstring, log level
# return 0:OK -1:error
def paas_log(logstring,level):
    "paas_log"
    if(level == LOG_ERROR):
        ret = ensure_log_file(LOG_FILENAME_ERROR)
        if(ret < 0):
            return -1
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS ERROR:'
        logstr = timestr + logstr +'\n' + logstring+ '\n'
        try:
            fd = open(LOG_FILENAME_ERROR,'a')
            fd.write(logstr)
            fd.close()
        except IOError as e:
            print 'write error-log error:%s' % str(e)
            return -1        
    else:
        ret = ensure_log_file(LOG_FILENAME_INFO)
        if(ret < 0):
            return -1
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS INFO:'
        logstr = timestr + logstr +'\n' + logstring + '\n'
        try:
            fd = open(LOG_FILENAME_INFO,'a')
            fd.write(logstr)
            fd.close()
        except IOError as e:
            print 'write info-log error:%s' % str(e)
            return -1
    return 0 

# get ldap_server from the configure file
def get_ldap_server():
    "get_ldap_server"
    fh = os.popen ('cat /etc/eucalyptus/eucalyptus-ldap.conf')
    setconfig = 1
    for ln in fh.readlines ():
        if 'LDAP_SERVER' in ln:
            ln = ln.strip (' \n')
            ls = ln.rsplit('"')
            ldap_server = ls[1]
            setconfig = 0
            break;
    if(setconfig):
        return None
    return ldap_server

# get localhost public ip
def get_local_publicip():
    "get_local_publicip"
    ldapip = get_ldap_server()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ldapip,80))
    hostip = s.getsockname()[0]
    return hostip

# ensure rescue file root is exist, if not create it
# output: 0:OK -1:error occur 
def ensure_rescue_path():
    "ensure_rescue_path"
    if os.path.exists(RESCUE_ROOT_PATH):
        return 0
    else:
        try:
            os.makedirs(RESCUE_ROOT_PATH)
        except:
            log_string = 'Create rescue file root error!'
            paas_log(log_string,LOG_ERROR)
            return -1
    return 0  
  
# check whether rescue file root path is exist, if it is exist and empty, then delete it
# output: 0:OK  -1:error occur  positive integer: it is not empty, can not be delete
def check_rescue_path():
    "heck_rescue_path"
    if os.path.exists(RESCUE_ROOT_PATH):
        filelist = os.listdir(RESCUE_ROOT_PATH)
        if len(filelist) == 0 :
            try:
                os.rmdir(RESCUE_ROOT_PATH)
            except:
                log_string = 'delete rescue root error!'
                paas_log(log_string,LOG_ERROR)
                return -1
            return 0
        else:
            return len(filelist)
    else:
        return 0 

# save a pending instance info to local file
# input ip:nc ip address,instance_id:instance id
# return 0: OK -1:error occur
def save_pending_instance(ip,instance_id):
    "save_pending_instance"
    if type(instances[ip][instance_id]) != DictType:
        return -1
    else:
        if instances.has_key(ip):
            nc =instances[ip] 
            if nc.has_key(instance_id):
                imageId = instances[ip][instance_id]['imageId']
                imageURL = instances[ip][instance_id]['imageURL']
                kernelId = instances[ip][instance_id]['kernelId']
                kernelURL = instances[ip][instance_id]['kernelURL']
                ramdiskId = instances[ip][instance_id]['ramdiskId']
                ramdiskURL = instances[ip][instance_id]['ramdiskURL']
                reservationId = instances[ip][instance_id]['reservationId']
                userId = instances[ip][instance_id]['userId']
                updateTime = instances[ip][instance_id]['updateTime']
                keyNameinstances[ip][instance_id]['keyName']
                memorySize = instances[ip][instance_id]['params']['memorySize']
                diskSize = instances[ip][instance_id]['params']['diskSize']
                numberOfCores = instances[ip][instance_id]['params']['numberOfCores']
                vlan = instances[ip][instance_id]['ncnet']['vlan']
                publicMac = instances[ip][instance_id]['ncnet']['publicMac']
                privateMac = instances[ip][instance_id]['ncnet']['privateMac']
                publicIp = instances[ip][instance_id]['ncnet']['publicIp']
                privateIp = instances[ip][instance_id]['ncnet']['privateIp']
                userData = instances[ip][instance_id]['userData']
                aunchIndex = instances[ip][instance_id]['launchIndex']
            else:
                return -1
        else:
            return -1
        instance_rescue_file = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'info'
        instance_rescue_fmt = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'fmt'
        rev = ensure_rescue_path()
        if rev < 0:
            return rev
        #struct pack format
        fmt = '%ds' % len(imageId)                #imageId
        fmt = fmt + '%ds' % len(imageURL)         #imageURL
        fmt = fmt + '%ds' % len(kernelId)         #kernelId
        fmt = fmt + '%ds' % len(kernelURL)        #kernelURL
        fmt = fmt + '%ds' % len(ramdiskId)        #ramdiskId
        fmt = fmt + '%ds' % len(ramdiskURL)       #ramdiskURL
        fmt = fmt + '%ds' % len(reservationId)    #reservationId
        fmt = fmt + '%ds' % len(userId)           #userId
        fmt = fmt +'i'                            #updateTime
        fmt = fmt + '%ds' % len(keyName)          #keyName
        fmt = fmt +'l'                            #memorySize
        fmt = fmt +'l'                            #diskSize
        fmt = fmt +'l'                            #numberOfCores
        fmt = fmt +'l'                            #vlan
        fmt = fmt + '%ds' % len(publicMac)        #publicMac
        fmt = fmt + '%ds' % len(privateMac)       #privateMac
        fmt = fmt + '%ds' % len(publicIp)         #publicIp
        fmt = fmt + '%ds' % len(privateIp)        #privateIp
        fmt = fmt + '%ds' % len(userData)         #userData
        fmt = fmt + '%ds' % len(launchIndex)      #imageURL
        try:
            bytes_in = struct.pack(fmt,imageId,imageURL,kernelId,kernelURL,ramdiskId,ramdiskURL,reservationId,userId,updateTime,\
keyName,memorySize,diskSize,numberOfCores,vlan,publicMac,privateMac,publicIp,privateIp,userData,imageURL)
        except:
            log_string = 'struct pack error!'
            paas_log(log_string,LOG_ERROR)
            return -1
        try:
            binfile=open(instance_rescue_file,'wb')
        except:
            log_string = 'open file:%s error!' % instance_rescue_file
            paas_log(log_string,LOG_ERROR)
            return -1
        try:
            binfile.write(bytes_in)
        except:
            log_string = 'binfile write file:%s error!' % instance_rescue_file
            paas_log(log_string,LOG_ERROR)
            return -1
        binfile.close()
        try:
            fd = open(instance_rescue_fmt,'a')
            fd.writelines([fmt,])
            fd.close()
        except IOError as e:
            log_string = 'instance_rescue_fmt io error:%s' % str(e)
            paas_log(log_string,LOG_ERROR)
            return -1
    return 0

# rescue one pending instance from local file
# input ip:nc ip address,instance_id:instance id
# return 0: OK -1:error occur
def rescue_instance(ip,instance_id):
    "rescue_instance"
    instance_rescue_file = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'info'
    instance_rescue_fmt = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'fmt'
    fmt = None
    try:
        fd = open(instance_rescue_fmt,'r')
        fmt = fd.readline()
        fd.close()
    except IOError as e:
        log_string = 'instance_rescue_fmt io error:%s' % str(e)
        paas_log(log_string,LOG_ERROR)
        return -1
    bytes_out = None
    try:
        binfile_out = open(instance_rescue_file,'rb') 
        bytes_out = binfile_out.read()
        binfile_out.close()
    except:
        log_string = 'read rescue file:%s error' % instance_rescue_file
        paas_log(log_string,LOG_ERROR)
        return -1
    try:
        imageId_get,imageURL_get,kernelId_get,kernelUR_getL,ramdiskId_get,ramdiskURL_get,reservationId_get,userId_get,\
updateTime_get,keyName_get,memorySize_get,diskSize_get,numberOfCores_get,vlan_get,publicMac_get,privateMac_get,\
publicIp_get,privateIp_get,userData_get,imageURL_get = struct.unpack(fmt,bytes_out)
    except:
        log_string = 'struct unpack error!'
        paas_log(log_string,LOG_ERROR)
        return -1
    if instances.has_key(ip):
        nc = instances[ip]
        if nc.has_key(instance_id):                                   # in case reload info
            instances[ip][instance_id]['imageId'] = imageId_get
            instances[ip][instance_id]['imageURL'] = imageURL_get
            instances[ip][instance_id]['kernelId'] = kernelId_get
            instances[ip][instance_id]['kernelURL'] = kernelURL_get
            instances[ip][instance_id]['ramdiskId'] = ramdiskId_get
            instances[ip][instance_id]['ramdiskURL'] = ramdiskURL_get
            instances[ip][instance_id]['reservationId'] = reservationId_get
            instances[ip][instance_id]['userId'] = userId_get
            instances[ip][instance_id]['updateTime'] = updateTime_get
            instances[ip][instance_id]['keyName'] = keyName_get
            instances[ip][instance_id]['params']['memorySize'] = memorySize_get
            instances[ip][instance_id]['params']['diskSize'] = diskSize_get
            instances[ip][instance_id]['params']['numberOfCores'] = numberOfCores_get
            instances[ip][instance_id]['ncnet']['vlan'] = vlan_get
            instances[ip][instance_id]['ncnet']['publicMac'] = publicMac_get
            instances[ip][instance_id]['ncnet']['privateMac'] = privateMac_get
            instances[ip][instance_id]['ncnet']['publicIp'] = publicIp_get
            instances[ip][instance_id]['ncnet']['privateIp'] = privateIp_get
            instances[ip][instance_id]['userData'] = userData_get
            instances[ip][instance_id]['stateName'] = 'Pending' 
            instances[ip][instance_id]['stateCode'] = PENDING
            instances[ip][instance_id]['deleteflag'] = 0 
            instances[ip][instance_id]['launchIndex'] = launchIndex_get
        else:                                                         # IP exist but instance id not exist
            instance_old = {}
            instance_old['params'] = {}
            instance_old['ncnet'] = {}
            instance_old['imageId'] = imageId_get
            instance_old['imageURL'] = imageURL_get
            instance_old['kernelId'] = kernelId_get
            instance_old['kernelURL'] = kernelURL_get
            instance_old['ramdiskId'] = ramdiskId_get
            instance_old['ramdiskURL'] = ramdiskURL_get
            instance_old['reservationId'] = reservationId_get
            instance_old['userId'] = userId_get
            instance_old['updateTime'] = updateTime_get
            instance_old['keyName'] = keyName_get
            instance_old['params']['memorySize'] = memorySize_get
            instance_old['params']['diskSize'] = diskSize_get
            instance_old['params']['numberOfCores'] = numberOfCores_get
            instance_old['ncnet']['vlan'] = vlan_get
            instance_old['ncnet']['publicMac'] = publicMac_get
            instance_old['ncnet']['privateMac'] = privateMac_get
            instance_old['ncnet']['publicIp'] = publicIp_get
            instance_old['ncnet']['privateIp'] = privateIp_get
            instance_old['userData'] = userData_get
            instance_old['launchIndex'] = launchIndex_get
            instance_old['stateName'] = 'Pending'
            instance_old['stateCode'] = PENDING
            instance_old['deleteflag'] = 0 
            instances[ip] = instance_old
    else:                                                             #IP not exist        
        instances[ip] = {}
        instance_old = {}
        instance_old['params'] = {}
        instance_old['ncnet'] = {}
        instance_old['imageId'] = imageId_get
        instance_old['imageURL'] = imageURL_get
        instance_old['kernelId'] = kernelId_get
        instance_old['kernelURL'] = kernelURL_get
        instance_old['ramdiskId'] = ramdiskId_get
        instance_old['ramdiskURL'] = ramdiskURL_get
        instance_old['reservationId'] = reservationId_get
        instance_old['userId'] = userId_get
        instance_old['updateTime'] = updateTime_get
        instance_old['keyName'] = keyName_get
        instance_old['params']['memorySize'] = memorySize_get
        instance_old['params']['diskSize'] = diskSize_get
        instance_old['params']['numberOfCores'] = numberOfCores_get
        instance_old['ncnet']['vlan'] = vlan_get
        instance_old['ncnet']['publicMac'] = publicMac_get
        instance_old['ncnet']['privateMac'] = privateMac_get
        instance_old['ncnet']['publicIp'] = publicIp_get
        instance_old['ncnet']['privateIp'] = privateIp_get
        instance_old['userData'] = userData_get
        instance_old['launchIndex'] = launchIndex_get
        instance_old['stateName'] = 'Pending'
        instance_old['stateCode'] = PENDING
        instance_old['deleteflag'] = 0 
        instances[ip] = instance_old
    return 0

# delete instance local file
# input ip:nc ip address,instance_id:instance id
# return 0: OK -1:error occur
def instance_running_notify(ip,instance_id):
    "instance_run_notify"
    instance_rescue_file = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'info'
    instance_rescue_fmt = RESCUE_ROOT_PATH + '/' + ip + '_' + instance_id + '_' + 'fmt'
    if os.path.exists(instance_rescue_file):
        try:
            os.remove(instance_rescue_file)
        except:
            log_string = 'remove file:%s error' % instance_rescue_file
            paas_log(log_string,LOG_ERROR)
            return -1
    if os.path.exists(instance_rescue_fmt):
        try:
            os.remove(instance_rescue_fmt)
        except:
            log_string = 'remove file:%s error' % instance_rescue_fmt
            paas_log(log_string,LOG_ERROR)
            return -1   
    return 0

# update local file rescue info
# return 0:OK -1:error occur
def update_rescue_info():
    "update_rescue_info"
    for ip in instances:
        if(ip == 'error'):
            pass
        else:
            nc = instances[ip]
            for id in nc:
                rev = instance_running_notify(ip,id)
                if rev < 0:
                    log_string = 'instance_running_notify error!'
                    paas_log(log_string,LOG_ERROR)
                    return -1
                else:
                    log_string = 'rescue_adaptor_crash OK!'
                    paas_log(log_string,LOG_INFO)
    ret = check_rescue_path()
    if ret < 0:
        log_string = 'check_rescue_path error!'
        paas_log(log_string,LOG_ERROR)
        return -1
    else:
        log_string = 'check_rescue_path OK!'
        paas_log(log_string,LOG_INFO)
    return 0

# rescue infomation from local file after cc-adaptor crashed
# return 0:OK -1:error occur
def rescue_adaptor_crash():
    "rescue_adaptor_crash"
    rev = check_rescue_path()
    if rev < 0:
        return -1
    else:
        if rev == 0:
                return 0
        else:
            filelist = os.listdir(RESCUE_ROOT_PATH)
            if len(filelist) == 0 :
                return -1
            for filename in filelist:
                if '_' in filename:
                    if 'info' in filename:
                        ls = filename.rsplit('_')
                        ip = ls[0]
                        instance_id = ls[1]
                        res = rescue_instance(ip,instance_id)
                        if res < 0:
                            return -1
                    else:
                        pass
                else:
                    pass
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
        log_string = 'login_ldap error!'
        paas_log(log_string,LOG_ERROR)
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
                        intval = lll.get(key)
                        intval =  intval[0]    
                        interval = int(intval) 
                        break                  
    except ldap.LDAPError, e:
        log_string = 'get_interval_time error!'
        paas_log(log_string,LOG_ERROR)
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
                        intval = lll.get(key)
                        intval =  intval[0]    
                        timeout = int(intval) 
                        break                  
    except ldap.LDAPError, e:
        log_string = 'get_timeout_time error!'
        paas_log(log_string,LOG_ERROR)
        return -1  
    return timeout


# chesk whether nc is alive
# input url: nc ip
# return 0: nc does not exist -1:nc is dead 1: nc is alive
def check_nc_alive(url):
    "check_nc_alive"
    if resources.has_key(url):
        now = time.time()
        now = int(now) 
        resource_info = resources[url]
        updatetime = resource_info['updateTime']
        ldap_uri,user_name,password = get_ldap_info()
        interval = get_interval_time(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,INTERVAL_KEY)
        if(interval < 0):
            interval = DEFAULT_INTERVAL
            log_string = "get_interval_time error!, use default value"
            paas_log(log_string,LOG_ERROR)
        gaptime = now - updatetime
        interval = interval*2
        if(gaptime > interval):        # nc is dead
            log_string = 'nc is dead'
            paas_log(log_string,LOG_ERROR)
            return -1
        else:                          # nc is alive
            return 1
    else:                              # nc does not exist
        log_string = 'nc does not exist'
        paas_log(log_string,LOG_INFO)
        return 0

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
        log_string = 'get_rabbitmq_ip error!'
        paas_log(log_string,LOG_ERROR)
        return None 
    return amqpip

#clean up the timeout instances infomation
def clean_up_timeout():
    "clean_up_timeout"
    ldap_uri,user_name,password = get_ldap_info()
    timeout = get_timeout_time(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,TIMEOUT_KEY)
    now = time.time()
    now = int(now)
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

# format instances info to a string
# input instances info dictionary
# output string
def format_instances(instances_info):
    "format_instances"
    stringinstances = ''
    if stringinstances is None:
        return stringinstances
    if type(instances_info) != DictType:
        return stringinstances
    for nkey in instances_info:
        rl = instances_info[nkey]
        stringinstance = ''
        stringinstance = BLANCK_SPACES + 'instanceId' + ':' + rl['instanceId'] + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'retries' + ':' + str(rl['retries']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'stateName' + ':' + str(rl['stateName']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'stateCode' + ':' + str(rl['stateCode']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'state' + ':' + str(rl['state']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'launchTime' + ':' + str(rl['launchTime']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + 'params' + ':' + str(rl['params']) + '\n'
        stringinstance = stringinstance + BLANCK_SPACES + '\n'
        stringinstances = stringinstances + stringinstance
    return stringinstances


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
        display_instances()
        retv = check_nc_alive(url)
        if retv < 1:
            info = ResourceInfo()
            return info
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
                    else:
                        nodeMemUsed = nodeMemUsed + instance['params']['memorySize']
                        cores = cores + instance['params']['numberOfCores']             
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
            info = ResourceInfo(nodeStatus=resource_info['nodeStatus'], memorySizeMax=memorySizeTotal, \
memorySizeAvailable=memorySizeAvail,diskSizeMax=resource_info['diskSizeMax']/1024, \
diskSizeAvailable=resource_info['diskSizeAvailable']/1024,numberOfCoresMax=int(resource_info['numberOfCoresMax']), \
numberOfCoresAvailable=CoresAvailable, publicSubnets=resource_info['publicSubnets'])
        else:
            info = ResourceInfo()
            log_string = 'senderResource:nc not find (%s)' % (url)
            paas_log(log_string,LOG_INFO)
        switch.release()
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
                    nCInstParams = NCInstParams(memorySize = instance_info['params']['memorySize'], diskSize =instance_info['params']['diskSize'] , \
numberOfCores = instance_info['params']['numberOfCores'] )
                    nCNetConf = NCNetConf(vlan = instance_info['ncnet']['vlan'], publicMac = instance_info['ncnet']['publicMac'], \
privateMac = instance_info['ncnet']['privateMac'], publicIp = instance_info['ncnet']['publicIp'], privateIp = instance_info['ncnet']['privateIp'])
                    ncSpiceInfo =  NCSpiceInfo(hostIp = 'error', port = 0, passwd = 'error' )
                    ncVolume1 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                    ncVolume2 = NCVolume(volumeId = 'error', remoteDev = 'error', localDev = 'error', stateName = 'fake')
                    ncVolume = [ncVolume1,ncVolume2]
                    instance_imageid = instance_info['imageId'];
                    try:
                        info = InstanceInfo(instanceId=instance_info['instanceId'], imageId=instance_imageid, imageURL=instance_info['imageURL'], \
kernelId=instance_info['kernelId'],kernelURL=instance_info['kernelURL'], ramdiskId=instance_info['ramdiskId'],ramdiskURL=instance_info['ramdiskURL'], \
reservationId=instance_info['reservationId'],userId=instance_info['userId'], retries=instance_info['retries'], stateName=instance_info['stateName'], \
stateCode=instance_info['stateCode'], state=instance_info['state'], keyName=instance_info['keyName'], privateDnsName=instance_info['privateDnsName'], \
dnsName=instance_info['dnsName'], launchTime=instance_info['launchTime'], terminationTime=instance_info['terminationTime'], params=nCInstParams, \
ncnet=nCNetConf,userData=instance_info['userData'], launchIndex=instance_info['launchIndex'], groupNames=ncgroupNames, \
groupNamesSize=instance_info['groupNamesSize'],volumes=ncVolume, volumesSize=instance_info['volumesSize'], ncspiceinfo=ncSpiceInfo, \
bundle=instance_info['bundle'])                   
                        list_info.append(info)
                    except e:
                        log_string = 'InstanceInfo error'
                        paas_log(log_string,LOG_ERROR)
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
                NCNetConf = {'vlan':CCNetConf.vlan, 'publicMac':CCNetConf.publicMac, 'privateMac':CCNetConf.privateMac, 'publicIp':CCNetConf.publicIp, \
'privateIp':CCNetConf.privateIp}
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
                NCNetConf = {'vlan':CCNetConf.vlan, 'publicMac':CCNetConf.publicMac, 'privateMac':CCNetConf.privateMac, 'publicIp':CCNetConf.publicIp, \
'privateIp':CCNetConf.privateIp}
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
        res = save_pending_instance(ip,instance_id)                          # save original infomation to local file
        if(res < 0):
            log_string = 'save_pending_instance error'
            paas_log(log_string,LOG_ERROR) 
        else:
            log_string = 'save_pending_instance ok'
            paas_log(log_string,LOG_INFO)        
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
        rev = instance_running_notify(url,instanceId)
        if rev < 0:
            log_string = 'instance_running_notify error!'
            paas_log(log_string,LOG_ERROR)
            return -1
        else:
            log_string = 'rescue_adaptor_crash OK!'
            paas_log(log_string,LOG_INFO)  
        ret = check_rescue_path()
        if ret < 0:
            log_string = 'check_rescue_path error!'
            paas_log(log_string,LOG_ERROR)
            return -1
        else:
            log_string = 'check_rescue_path OK!'
            paas_log(log_string,LOG_INFO)                
        return 'receive OK!'

# listen from cc and reponse to cc
class listen_cc(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        handler = NCInfoServletHandler()
        processor = NCInfoServlet.Processor(handler)
        host_ip = get_local_publicip()
        transport = TSocket.TServerSocket(host_ip,9090)
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
            nc_ip = nc_raw['ip']
            resource_info = nc_raw['resource']
            log_string = 'cc-adaptor received resource from nc:%s' % (str(resource_info))
            paas_log(log_string,LOG_INFO)
            instances_info = nc_raw['instances']
            log_string = format_instances(instances_info)
            paas_log(log_string,LOG_INFO)
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
                            original_delflag = instances[nc_ip][lgkey]['deleteflag']                                                         
                            if original_delflag == 0:
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
            resource_info['updateTime'] = now
            resources[nc_ip] =  resource_info
            ret = update_rescue_info()
            if ret < 0:
                log_string = 'update_rescue_info error!'
                paas_log(log_string,LOG_ERROR)
            else:
                log_string = 'update_rescue_info OK!'
                paas_log(log_string,LOG_INFO)
            try:
                clean_up_timeout()
                log_string = 'clean_up_timeout OK!'
                paas_log(log_string,LOG_INFO)
            except:
                paas_log('clean_up_timeout error',LOG_ERROR)            
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
        retv = rescue_adaptor_crash()                        # rescue cc-adaptor crash
        if retv < 0:
            log_string = 'rescue_adaptor_crash error!'
            paas_log(log_string,LOG_ERROR)
        else:
            log_string = 'rescue_adaptor_crash OK!'
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
def preInit (user_data):
    "normal main interface"
    print "pre_init starting..."
    monitor_thread =  main_thread()
    monitor_thread.start()
    log_string = 'main thread starting and pre_init return'
    paas_log(log_string,LOG_INFO) 
    return 0     
 
def postInit (user_data):
  pass
