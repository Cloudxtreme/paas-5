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
import libvirt
import boto
import getopt, sys, os, stat
import tarfile
import gzip
import Queue
import thread
import threading
import time
import datetime
import logging
import string, StringIO
import ldap
import socket
import fcntl
import struct
import commands
from xml.dom.minidom import Document
from xml.dom import minidom
from hashlib import sha1 as sha
from M2Crypto import BN, EVP, RSA, util, Rand, m2, X509
from binascii import hexlify, unhexlify
from subprocess import *
from types import *
import platform
import urllib
import re
import shutil
from amqplib.client_0_8 import Message
from amqplib import client_0_8 as amqp

LIBVIRT_QUERY_RETRIES = 2             #libvirt

BASE_DN = 'cn=clc,o=cloudbot,o=sinobot'
SEARCH_FILTER = 'ou=prefrencePrompt'
INTERVAL_KEY = 'NCSenserInterval'
AMQP_KEY = 'MaqpServerIp'
DEFAULT_INTERVAL = 2
EN_CHECK_TIMES = 50
WAIT_THREAD_JOB = 3600.0                # main thread wait job thread timed,second

# pthread mutex 
switch = threading.Lock() 
# the global flag which identify whether the job thread is running 
g_job_thread_error = 0 


LOG_PATH_ROOT     = os.path.expanduser('~') + '/.luhya/logs'     # log file root
LOG_FILENAME_ERROR = LOG_PATH_ROOT+'/paas_ncsensor_error.log'   # log error file name
LOG_FILENAME_INFO = LOG_PATH_ROOT+'/paas_ncsensor_info.log'     # log info file name
MAX_LOGFILE_SIZE = 100*1024*1024L                               # 100M max lof file size
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

# set g_job_thread_error = 1, it maens job thread error occur
def set_thread_error():
    "set_thread_error"
    switch.acquire() 
    global g_job_thread_error
    g_job_thread_error = 1
    switch.release()


# set g_job_thread_error = 0
def unset_thread_error():
    "unset_thread_error"
    switch.acquire()
    global g_job_thread_error
    g_job_thread_error = 0
    switch.release()

# check wether job thread is wrong
# return 0:ok 1:error occur
def is_thread_error():
    "is_thread_error"
    flag = 0
    switch.acquire()
    global g_job_thread_error
    flag = g_job_thread_error
    switch.release()
    return flag

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

# login to ldap server
def login_ldap(ldap_uri,user_name, password):
    "login_ldap"
    try:  
        Server = ldap_uri   
        Scope = ldap.SCOPE_SUBTREE   
        ln = ldap.initialize(Server)  
        ln.set_option(ldap.OPT_REFERRALS, 0) 
        ln.protocol_version = 3  
        ret = ln.simple_bind_s(user_name, password) 
        return ln 
    except ldap.LDAPError, e:  
        print e  
        return None  

# Get the interval time from ldap server
def get_interval_time(ldap_uri,user_name,password,baseDN,searchFilter,key):
    "get_interval_time"
    interval = 10
    ncldap = login_ldap(ldap_uri,user_name, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None 
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

# Get RabbitMQ server ip from ldap server
def get_rabbitmq_ip(ldap_uri,user_name,password,baseDN,searchFilter,key):
    "get_rabbitmq_ip"
    amqpip = "localhost"
    ncldap = login_ldap(ldap_uri,user_name, password)
    if ncldap == None:
        return -1
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None 
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
                        pairip = lll.get(key)
                        amqpip =  pairip[0]    
                        break                  
    except ldap.LDAPError, e:
	print e
        return None 
    return amqpip

# get all running instances info
def get_instances_info(conn):
    "get_instances_info"
    instances = {}
    instance_state = ['no_state','running','blocked','pause','shutdown','shutoff','crashed','staging','booting','canceled','pending','extant','teardown','total_state']
    for id in conn.listDomainsID():
        try:
	    dom = conn.lookupByID(id)
        except:
            log_string = 'conn.lookupByID thrown except'
            paas_log(log_string,LOG_INFO)
            return None
        instance = {}
        instanceid = dom.name()
        instance['instanceId'] = dom.name()
        instance['imageId'] = ''
        instance['imageURL'] = ''
        instance['kernelId'] = ''
        instance['kernelURL'] = ''
        instance['ramdiskId'] = ''
        instance['ramdiskURL'] = '' 
        instance['reservationId'] = ''
        instance['userId'] = ''
        instance['retries'] = LIBVIRT_QUERY_RETRIES
        stateid = dom.info()[0]
        instance['stateName'] = instance_state[stateid]
        instance['stateCode'] = stateid
        instance['state'] = stateid
        instance['keyName'] = ''
        instance['privateDnsName'] = ''
        instance['dnsName'] = ''
        launchTime_nl = dom.info()[4]
        launchTime_nsl = launchTime_nl*0.000000001
        launchTime = time.time() - launchTime_nsl
        launchTime = int(launchTime)
        instance['launchTime'] = launchTime   
        instance['terminationTime'] = 0
        NCInstParams = {'memorySize':dom.info()[1],'diskSize':0,'numberOfCores':dom.info()[3]}
        instance['params'] = NCInstParams
        NCNetConf = {}
        NCNetConf = {'vlan':0, 'publicMac':'', 'privateMac':'', 'publicIp':'0.0.0.0', 'privateIp':'0.0.0.0'} #TODO net mode bridge
        instance['ncnet'] = NCNetConf
        instance['userData'] = ''
        instance['launchIndex'] = ''
        instance['groupNamesSize'] = 0
        instance['volumesSize'] = 0 
        instance['ncspiceinfo'] = {}
        instance['bundle'] = 0
        instances[instanceid] = instance
        dom = 0
    return instances

#get eucalyptus-nc status
def get_nc_status():
    "get_nc_status"
    fh = os.popen ('status eucalyptus-nc')
    flag = 0
    for ln in fh.readlines ():
        if 'start/running' in ln:
            flag = 1
            break
        else:
            status = ln
            flag = 2
            break
    if (flag == 1):
        return 'start/running'
    if (flag == 2):
        return status
    else:
        return 'stop'

#get the host total memery
def get_mem_total():
    "get_mem_total"
    configs = {}
    fh = os.popen ('cat /proc/meminfo')
    for ln in fh.readlines ():
        if 'MemTotal:' in ln:
            ln = ln.replace('kB', '');
            ln = ln.replace(' ', '');
            ln = ln.strip (' \n')
            for pair in ln.split ():
                key, val = pair.split (':')
                configs[key] = val
            break   
    return configs.get('MemTotal')


# get the host netconfig info 
def get_net_config():
    "get_net_config"
    configs = {}
    fh = os.popen ('ifconfig')
    for ln in fh.readlines ():
        if 'inet addr:' in ln:
            ln = ln.replace ('inet addr', 'addr')
            ln = ln.strip (' \n')
            for pair in ln.split ():
                key, val = pair.split (':')
                configs[key] = val
            break   
    return (configs.get('addr'), configs.get('Mask'))

# get the host disk info, it return the total disk space and free space
def get_disk_status():
    st = os.statvfs('/')
    total = st.f_blocks*st.f_bsize/1024
    avail = st.f_bavail*st.f_bsize/1024
    return total,avail
        
# get nc max cores from the configure file
def get_max_cores():
    "get_max_cores"
    fh = os.popen ('cat /etc/eucalyptus/eucalyptus.conf') #identify file exist
    for ln in fh.readlines ():
        if 'MAX_CORES' in ln:
            ln = ln.strip (' \n')
            ls = ln.rsplit('"')
            break
    return ls[1]

# get the used nc cores from libvirt interface
def get_used_cores(conn):
    "get_used_cores"
    cores = 0
    for id in conn.listDomainsID():
	dom = conn.lookupByID(id)
        cores = cores+dom.info()[3]
    return cores


# get describe resource info    
def get_resource_info():
        "get_resource_info"
	dt,df = get_disk_status()
	ip = get_local_publicip()
	netconf = ip + '/' + '0.0.0.0'
	resource = {'nodeStatus':get_nc_status(), \
'memorySizeMax':get_mem_total(),\
'diskSizeMax':dt, 'diskSizeAvailable':df, \
'numberOfCoresMax':get_max_cores(), \
'publicSubnets':netconf}
	return resource  
	
# encapsulate all data,include describeresoure and describeinstance
def data_encapsulate(conn):
    "data_encapsulate"
    ip = get_local_publicip()                     
    log_string = 'get_local_publicip:ip/%s' % (ip)
    paas_log(log_string,LOG_INFO)
    resource = get_resource_info()
    log_string = 'get_resource_info:resource/%s' % (str(resource))
    paas_log(log_string,LOG_INFO)
    instances = get_instances_info(conn)
    if(instances == None):
        return None
    log_string = 'get_instances_info:instances/%s' % (str(instances))
    paas_log(log_string,LOG_INFO)
    sendmsg = {'ip':ip,'resource':resource,'instances':instances}
    return sendmsg  

# send Message to RabbitMQ
# input connected rabbotmq channel
def send_Message(chan,content):
    "send_Message"
    try:
        msg = Message(content_type='text/plain',application_headers=content,delivery_mode=1,priority=7)
        chan.basic_publish(msg,exchange="sorting_room",routing_key="jason")
        log_string = 'basic_publish:%s' % (str(content))
        paas_log(log_string,LOG_INFO)
    except:
        log_string = 'send messge to Rabbitmq error:%s' % (str(content))
        paas_log(log_string,LOG_INFO)
        return -1
    return 0

# check whether babbitmq is alive
# server:Rabbitmq server,port:rabbitmq port
# return 1:alive 0:dead 
def check_amqp(server,port):
    "check_amqp"
    flag = 0
    rabbitURI ='%s:%d'%(server,port) 
    try:                     
        conn = amqp.Connection(host=rabbitURI, userid="guest", password="guest", virtual_host="/", insist=False)
        if(conn != None):
            flag = 1
    except:
        log_string = 'Rabbitmq stopped'
        paas_log(log_string,LOG_ERROR)    
    return flag

# check rabbitmq times
# input trytimes:times try to check rabbitmq,server:rabbitmq server,port:rabbitmq port
# return 0:ok -1:error
def check_amqp_times(times,server,port):
    "check_amqp_times"
    flag = 1
    inner_trytimes = times
    if (inner_trytimes < 2):           
        inner_trytimes = 2                                             # at least try two times
    if (check_amqp(server,port)):
        return 0
    for i in range(inner_trytimes):
        time.sleep(LIBVIRT_QUERY_RETRIES)                                                                                                                                   
        if (check_amqp(server,port)):
            flag = 0
            break
    if(flag):
        log_string = 'Rabbitmq does not work,please check the rabbitmq server'
        paas_log(log_string,LOG_ERROR)
        return -1
    else:
        log_string = 'Rabbitmq is running'
        paas_log(log_string,LOG_INFO)
        return 0 

# check whether libvirt is alive
# return 1:alive 0:dead 
def check_libvirt():
    "check_libvirt"
    flag = 0
    status, output = commands.getstatusoutput('virsh list')
    index = output.find('Id Name')
    if status == 0:
        if index > -1:
            flag = 1
    if(flag == 0):
        log_string = 'libvirt stop:%s' % output
        paas_log(log_string,LOG_ERROR)
    return flag

# restart libvirt: /etc/init.d/libvirt-bin
# input trytimes:times try to retart libvirtd
# return 0:ok -1:error
def restart_libvirt_times(trytimes):
    "restart_libvirt"
    flag = 1
    inner_trytimes = trytimes
    if (inner_trytimes < 2):           
        inner_trytimes = 2                                             # at least try two times
    if (check_libvirt()):
        return 0
    for i in range(inner_trytimes):
        status, output = commands.getstatusoutput('/etc/init.d/libvirt-bin restart')            # try to start libvirt
        log_string = 'start libvirt-bin,command return status:%d,system ouput:%s' % (status,str(output))
        paas_log(log_string,LOG_ERROR)
        time.sleep(LIBVIRT_QUERY_RETRIES)                                                                                                                                   
        if (check_libvirt()):
            flag = 0
            break
    if(flag):
        log_string = 'Fail to start libvirt-bin'
        paas_log(log_string,LOG_ERROR)
        return -1
    else:
        log_string = 'start libvirt-bin ok'
        paas_log(log_string,LOG_INFO)
        return 0 

# check nc-sensor running environment, if libvirt is stopped, try to start it
# input trytimes:times try to retart libvirtd,server:rabbitmq server,port:rabbitmq port
# return 0: OK -1:libvirt error -2:rabbitam error
def check_environment_times(trytimes,server,port):
    "check_environment_times"
    if(check_libvirt()):
        pass
    else:
        ret = restart_libvirt_times(trytimes)
        if( ret < 0):
            return -1
    ret = check_amqp_times(trytimes,server,port)
    if(ret < 0):
        return -2
    else:
        return 0

# check nc-sensor running environment, if environment is not ready it will wait till it is ready.
# input trytimes:times try to retart libvirtd,server:rabbitmq server,port:rabbitmq port
# return 0: OK 
def check_environment(trytimes,server,port):
    "check_environment"
    env_ready = 1
    while env_ready:
        ret = check_environment_times(trytimes,server,port)
        if ret == 0:
            env_ready = 0
            break;
        else:
            if(ret == -1):
                log_string = 'libvirt stopped working'
                print log_string
                paas_log(log_string,LOG_ERROR)
            else:
                log_string = 'Rabbit stopped working'
                print log_string
                paas_log(log_string,LOG_ERROR)
    return 0

# listen from cc and reponse to cc
class nc_pthread_job(threading.Thread):
    def __init__(self, RabbitMQ_server,RabbitMQ_port,interval,threadCondition):
        threading.Thread.__init__(self)
        self.RabbitMQ_server = RabbitMQ_server
        self.RabbitMQ_port = RabbitMQ_port
        self.interval = interval
        self.threadCondition = threadCondition
    def run(self):
        try:    	
            conn = libvirt.open('qemu:///system')    
        except Exception as e:
            logging.error (" %s: connect to libvirt failed:%s\n" % (modname, e))
            log_string = 'open libvirt error!'
            paas_log(log_string,LOG_ERROR)
            self.threadCondition.acquire()  
            set_thread_error()
            self.threadCondition.notify()
            self.threadCondition.release()	 
            thread.exit()
        
        rabbitURI ='%s:%d'%(self.RabbitMQ_server,self.RabbitMQ_port)
        conn_rabbitmq = None
        
        try:
            conn_rabbitmq = amqp.Connection(host=rabbitURI, userid="guest", password="guest", virtual_host="/", insist=False)
            if(conn_rabbitmq == None):
                log_string = 'amqp.Connection error'
                paas_log(log_string,LOG_ERROR) 
                self.threadCondition.acquire()  
                set_thread_error()
                self.threadCondition.notify()
                self.threadCondition.release()
                conn.close() 	 
                thread.exit()
        except Exception as e:
            logging.error (" %s: connect to amqp server failed:%s\n" % (modname, e))
            log_string = 'amqp.Connection thrown occur'
            paas_log(log_string,LOG_ERROR) 
            self.threadCondition.acquire()  
            set_thread_error()
            self.threadCondition.notify()
            self.threadCondition.release()
            conn.close()	 
            thread.exit()
        chan = conn_rabbitmq.channel() 
        while True:
            content = data_encapsulate(conn)
            if(content == None):
                log_string = 'data_encapsulate error'
                paas_log(log_string,LOG_ERROR)
                self.threadCondition.acquire()  
                set_thread_error()
                self.threadCondition.notify()
                self.threadCondition.release()
                chan.close()
                conn_rabbitmq.close()
                conn.close()	
                thread.exit()                   
            res = send_Message(chan,content)
            if(res != 0):
                log_string = 'send_Message error'
                paas_log(log_string,LOG_ERROR)
                self.threadCondition.acquire()  
                set_thread_error()
                self.threadCondition.notify()
                self.threadCondition.release()
                chan.close()
                conn_rabbitmq.close()
                conn.close()	
                thread.exit()            
            else:
                log_string = 'send_Message:%s' % (str(send_Message))
                paas_log(log_string,LOG_INFO)
                time.sleep(self.interval)
        chan.close()                                          # only for routine
        conn_rabbitmq.close()
        conn.close()

# nc monitor thread,main thread
class nc_pthread_monitor(threading.Thread):
    "nc_pthread_monitor"
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        "monitor main interface"
        ldap_loop = 1
        while ldap_loop:
            try:
		ldap_uri,user_name,password = get_ldap_info()
		log_string = 'get_ldap_info:ldap_uri/%s,user_name/%s' % (ldap_uri,user_name)
		paas_log(log_string,LOG_INFO)    
		interval = get_interval_time(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,INTERVAL_KEY)
            except:
                interval = -1
            if interval > 0:
                log_string = 'get_interval_time:interval:%d' % (interval)
                paas_log(log_string,LOG_INFO)
                ldap_loop = 0
                break;
            else:
                log_string = 'get_interval_time error,please check whether ldap server is alive!'
                paas_log(log_string,LOG_ERROR)
                print log_string
                time.sleep(2)
        rabbit_loop = 1
        while rabbit_loop:
            amqpip = get_rabbitmq_ip(ldap_uri,user_name,password,BASE_DN,SEARCH_FILTER,AMQP_KEY) 
            log_string = 'get_rabbitmq_ip:amqpip/%s' % (amqpip)
            paas_log(log_string,LOG_INFO)    
            if (amqpip):
                RabbitMQ_server = amqpip
                rabbit_loop = 0
                break;
            else:
                log_string = 'get_rabbitmq_ip error,please check whether ldap server is alive!'
                paas_log(log_string,LOG_ERROR)
                time.sleep(2)

        RabbitMQ_port = 5672
        start_fisrt_time = 1
        restart_job_flag = 0
        threadCondition = threading.Condition()	
        while True:
            if(((start_fisrt_time > 0) or (restart_job_flag > 0))):    # the first time to start job thread, or it run after job thread runs abnormal
                #start/restart job thread
                # if check_environment will wait untill environment is ready
                check_environment(EN_CHECK_TIMES,RabbitMQ_server,RabbitMQ_port)
                unset_thread_error()
                job = nc_pthread_job(RabbitMQ_server,RabbitMQ_port,interval,threadCondition)
                job.setDaemon(True)
                job.start()
                if(restart_job_flag > 0):
                    if(restart_job_flag == 1):
                        log_string = 'job pthread had meet trouble,restarted job pthread'
                    else:					
                        log_string = 'job pthread stopped,restarted job pthread'
                    paas_log(log_string,LOG_ERROR)
                if(start_fisrt_time):
                    start_fisrt_time = 0
                if(restart_job_flag):
                    restart_job_flag = 0
            threadCondition.acquire()                          # monitor job thread starting
            try:
                ret = threadCondition.wait(WAIT_THREAD_JOB)    # it will implicit call threadCondition.release() before wait,and call threadCondition.acquire()
                if(ret != None):                               # after wait return, so we need threadCondition.release()again
                    log_string = 'threadCondition wait timed error'
                    paas_log(log_string,LOG_ERROR)
                    sys.exit()
            except:
                log_string = 'threadCondition wait timed error'
                paas_log(log_string,LOG_ERROR)
                sys.exit()
            threadCondition.release()
            if(job.isAlive()):
                if(is_thread_error()):                     #in case the job thread exit is not complete or job thread notify main thread
                    restart_job_flag = 1					
            else:
                restart_job_flag = 2


# the nc_sensor interface
def preInit (user_data):
    "pre_init"
    print 'pre_init starting ...'
    monitor = nc_pthread_monitor()
    monitor.start()                             # the thread will not exist after creater exist
    log_string = 'started nc_pthread_monitor pthread,pre_init return'
    paas_log(log_string,LOG_INFO)
    return 0     #sys.exit()


def postInit (user_data):
  pass
