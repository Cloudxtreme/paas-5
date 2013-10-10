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
# Author: tony li tony.li@sinobot.com.cn

import getopt, sys, os
import commands
from subprocess import *
import re
import shutil
import uuid
import random
import socket
import logging
import threading
import thread
import time
import hashlib
sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.interface import clcApi
from cloudbot.interface.ttypes import * 
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

import fcntl
import struct
import copy
from cloudbot.utils import OpenLdap,utility
import vmConfigEngine
from vmEngineType import *
from cloudbot.utils.const_def import *

g_server_resource = {'recvRate':0,'sendRate':0,'cpuUtilization':0}
g_source_switch = threading.Lock()
logger = utility.init_log()
g_backup_transactions = []
g_restore_transactions = []
g_backup_switch = threading.Lock()
g_restore_switch = threading.Lock()

g_all_heart_beat = {}
g_clc_ip = None
g_ldap_ip = None
g_wal_ip = None
g_resource_clc = {}
g_resource_switch = threading.Lock()
g_migrate_states = {}
g_migrate_switch = threading.Lock()
g_instance_info = {}
g_client_info = {}
g_vmconfig_list = []
g_image_list = []
g_vm_img_lock=threading.Lock()  # change global g_vmconfig_list and g_image_list used lock


# get point machine hard resource
def p_get_hard_source(IP,hdSource):
    logger.info('p_get_hard_source.....')
    ret = False
    g_resource_switch.acquire()
    hdResource = thd_service_list()
    hdResource.resource = hdSource
    if IP != None:
        paas_services = []
        ldap_ip = utility.get_ldap_server()
        service_id_list = OpenLdap.p_get_services_by_ip(ldap_ip,IP)
        for id in service_id_list:
            servInfo = thd_service()
            servInfo.service_id = id
            servInfo.is_alive = True
            paas_services.append(servInfo)
        
        hdResource.paas_services = paas_services
        g_resource_clc[IP] = hdResource
        ret = True
    else:
        logger.error('IP error!!!')
    g_resource_switch.release()
    logger.debug('p_get_hard_source:%s' %str(g_resource_clc))
    return ret

#when some service no heartbeat , to update the service start
def p_heart_dead_run(name,ip):
    logger.info('p_heart_dead_run():::name:%s IP:%s' %(name,ip))
    if name == None or ip == None:
        return
    global g_resource_clc
    
    if ip in g_resource_clc:
        for ln in g_resource_clc[ip].paas_services:
            if name == 'wal' and ln.service_id == thd_SERVICE_TYPE.CLOUD_WALRUS:
                ln.is_alive = False
            elif name == 'ldap' and ln.service_id == thd_SERVICE_TYPE.CLOUD_REGISTRY:
                ln.is_alive = False
            elif name == 'cluster' and ln.service_id == thd_SERVICE_TYPE.CLOUD_CC:
                ln.is_alive = False
    logger.info('p_heart_dead_run:%s' %str(g_resource_clc))
                

#to update the service heartbeat is alive
def p_heart_beat_isAlive():
    global g_all_heart_beat
    heartT = time.time()
    for name in g_all_heart_beat:
        for ip in g_all_heart_beat[name]:
            if (heartT - g_all_heart_beat[name][ip]) < 4:
                logger.debug(' %s server and IP:%s is alive ' %(name,ip))
            else:
                logger.warn(' server:%s and IP:%s is dead!!!' %(name,ip))
                p_heart_dead_run(name,ip)    
    heart = threading.Timer(4.0,p_heart_beat_isAlive)
    heart.start()

#to get server hard resource
class p_transmit_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('p_transmit_server_source_thread...')
        while True:
            if g_clc_ip!=None:
                hdSource = utility.utility_get_current_resource()
                g_source_switch.acquire()
                hdSource.net_receiverate = g_server_resource['recvRate']
                hdSource.net_sendrate = g_server_resource['sendRate']
                hdSource.cpu_utilization = g_server_resource['cpuUtilization']
                g_source_switch.release()
                hdSource.state = 'HW_STATUS_OK'
                if hdSource.cpu_utilization > VM_CPU_UTILIZATION:
                    hdSource.state = 'HW_STATUS_WARN'
            
                p_get_hard_source(g_clc_ip,hdSource)
            time.sleep(SERVER_SOURCE_INTV)

# get ip address
class p_get_ip_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        while True:
            logger.info('p_get_ip_thread...start')
            global g_clc_ip
            global g_ldap_ip
            global g_wal_ip
            
            g_clc_ip = utility.get_local_publicip()
            g_ldap_ip = utility.get_ldap_server()
            g_wal_ip ,port = OpenLdap.get_walrus_info(g_ldap_ip)
            if g_clc_ip != None and g_ldap_ip != None and g_wal_ip != None:
                logger.info('g_clc_ip:%s g_ldap_ip:%s g_wal_ip:%s' %(g_clc_ip,g_ldap_ip,g_wal_ip))
                break
            else:
                logger.info('waiting in p_get_ip_thread()')
            time.sleep(1)

#get all service in this system
class p_get_all_services_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('p_get_all_services_thread start ....')
        global g_all_heart_beat
        global g_ldap_ip
        global g_wal_ip
        while True:
            if g_wal_ip!=None and g_ldap_ip!=None:
                walTemp={}
                walTemp[g_wal_ip] = time.time()
                g_all_heart_beat['wal'] = walTemp
                ldapTemp = {}
                ldapTemp[g_ldap_ip] = time.time()
                g_all_heart_beat['ldap'] = ldapTemp
                ldap_ip = utility.get_ldap_server()
                clusterInfo = OpenLdap.luhya_get_clusterList(ldap_ip)
                if clusterInfo != None:
                    temp = {}
                    for ln in clusterInfo:
                        temp[ln.hostIp] = time.time()
                    g_all_heart_beat['cluster'] = temp
                    logger.info(g_all_heart_beat)
                    break
            time.sleep(1)
            logger.debug('waiting in p_get_all_services_thread()!!!')
            
# heartbeat
class p_heart_beat_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        p_heart_beat_isAlive()

def p_heart_beat_timer(ip,name):
    ret = True
    global g_all_heart_beat
    serID = ' '
    ldap_ip = utility.get_ldap_server()
    if ip != None and name != None:
        if name == 'cluster':
            serID = thd_SERVICE_TYPE.CLOUD_CC
        elif name == 'wal':
            serID = thd_SERVICE_TYPE.CLOUD_WALRUS
        elif name == 'ldap':
            serID = thd_SERVICE_TYPE.CLOUD_REGISTRY
        if g_all_heart_beat.has_key(name):
            p_heartbeat = g_all_heart_beat[name]
            if not p_heartbeat.has_key(ip):
                re = OpenLdap.p_is_register(ldap_ip,serID,ip)
                if re:
                   p_heartbeat[ip] = time.time()
                else:
                    ret = False
            else:
                p_heartbeat[ip] = time.time()
        else:
            re = OpenLdap.p_is_register(ldap_ip,serID,ip)
            if re:
                p_heartbeat = {}
                p_heartbeat[ip] = time.time()
                g_all_heart_beat[name] = p_heartbeat
            else:
                ret = False
    return ret

# if nc no heartbeat , update the service state
def p_nc_heart_beat_dead(ncIp,servID):
    if ncIp == None:
        return False
    global g_resource_clc
    ret = False
    if ncIp in g_resource_clc:
        for ln in g_resource_clc[ncIp].paas_services:
            if ln.service_id == servID:
                ln.is_alive = False
                ret = True
    return ret


# get run instance by user
def p_get_instance_info_list(userName):
    ins = [] 
    p_all_instances = g_instance_info.copy()
    for cluster in p_all_instances.keys():
        p_cluster = p_all_instances[cluster]
        if p_cluster!=None:
            for nodeIp in p_cluster.keys():
                node_live = False
                if g_resource_clc.has_key(nodeIp):
                    for ln in g_resource_clc[nodeIp].paas_services:
                        if ln.service_id == thd_SERVICE_TYPE.CLOUD_NC:
                            if not ln.is_alive :
                                del g_instance_info[cluster][nodeIp]
                            else:
                                node_live=True
                            break
                if not node_live:
                    continue

                p_instances = p_cluster[nodeIp][:]
                if p_instances!=None:
                    for insClient in p_instances:
                        if insClient.user==userName or OpenLdap.p_is_admin(utility.get_ldap_server(),userName):
                            ins.append(insClient)
    logger.info('p_get_instance_info_list instances:%s' %str(ins))
    return ins

# get run instance by user on point node
def p_get_instances_by_node(userName,nodeIp):
    ins = []
    insList = p_get_instance_info_list(userName)
    if insList!=None:
        for instance in insList:
			if instance.node_ip == nodeIp :
				ins.append(instance)
    logger.info('p_get_instances_by_node : %s' % str(ins))
    return ins

class p_backup_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        p_backup_thread_job()

class p_get_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('p_get_server_source_thread starting ...')
        while True:
            recvRate,sendRate = utility.p_get_net_rate()
            cpuUtilization = utility.get_current_cpuUtilization()
            g_source_switch.acquire()
            g_server_resource['recvRate'] = recvRate
            g_server_resource['sendRate'] = sendRate
            g_server_resource['cpuUtilization'] = cpuUtilization
            g_source_switch.release()
            time.sleep(SERVER_SOURCE_INTV)

class p_restore_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        p_restore_thread_job()


def p_backup_thread_job():
    while True:
        g_backup_switch.acquire()
        item = 0
        is_backup_now = False
        while item<len(g_backup_transactions):
            il = g_backup_transactions[item]
            if il.state=='BACKUP_FINISH' or il.state=='BACKUP_FAILED' :
				g_backup_transactions.remove(il)
				continue
            if il.state=='DUPLICATING' :
                is_backup_now=True
            item = item+1
        
        logger.debug('p_backup_thread_job all trans: %s ' % str(g_backup_transactions))            
        if not is_backup_now and len(g_backup_transactions)>0:
            transaction = g_backup_transactions[0]
            g_backup_transactions[0].state = 'DUPLICATING'
            OpenLdap.p_backup_instance(transaction.node_ip ,transaction.user_name,transaction.imag_id)
        g_backup_switch.release()
        time.sleep(BACKUP_INTERVAL)
        
def p_restore_thread_job():
    while True:
        g_restore_switch.acquire()
        item = 0
        is_restore_now = False
        while item<len(g_restore_transactions):
            il = g_restore_transactions[item]
            if il.state=='RESTORE_FINISH' or il.state=='RESTORE_FAILED' :
				g_restore_transactions.remove(il)
				continue
            if il.state=='RESTORING':
                is_restore_now=True
            item = item+1
        logger.debug('p_restore_thread_job all trans: %s ' % str(g_restore_transactions))
        if not is_restore_now and len(g_restore_transactions)>0:
            transaction = g_restore_transactions[0]
            g_restore_transactions[0].state = 'RESTORING'
            OpenLdap.p_restore_instance(transaction.node_ip ,transaction.user_name,transaction.image_id)
        g_restore_switch.release()
        time.sleep(BACKUP_INTERVAL)
           
def p_get_backup_transactionID_by_user_img(user,imageID):
	transID = None
	for transaction in g_backup_transactions:
		if(transaction.user_name == user and transaction.image_id == imageID):
			transID = transaction.transaction_id
	return transID

def p_get_restore_transactionID_by_user_img(user,imageID):
	transID = None
	for transaction in g_restore_transactions:
		if(transaction.user_name == user and transaction.image_id == imageID):
			transID = transaction.transaction_id
	return transID
	
def p_set_backup_state(user,imageID,state):
    ret = False
    logger.info('p_set_backup_state :%s ' % state)
    g_backup_switch.acquire()
    item = 0
    while item < len(g_backup_transactions):
        if(g_backup_transactions[item].user_name == user and g_backup_transactions[item].image_id == imageID):
            g_backup_transactions[item].state = state
            break
        item = item +1        
    logger.info('p_set_backup_state :trans: %s ' % str(g_backup_transactions))
    g_backup_switch.release()
    return ret
    
def p_set_restore_state(user,imageID,state):
    ret = False
    logger.info('p_set_restore_state :%s ' % state)
    g_restore_switch.acquire()
    item = 0
    while item < len(g_restore_transactions):
        if(g_restore_transactions[item].user_name == user and g_restore_transactions[item].image_id == imageID):
            g_restore_transactions[item].state = state
            break
        item = item +1        
    g_restore_switch.release()
    return ret

def p_set_backup_progress(user,imageID, progress):
    logger.info('p_set_backup_progress :%s ' % progress)
    g_backup_switch.acquire()
    item = 0
    while item < len(g_backup_transactions):
        if(g_backup_transactions[item].user_name == user and g_backup_transactions[item].image_id == imageID):
            g_backup_transactions[item].progress = progress
            break
        item = item +1
    g_backup_switch.release()
    return True

    
def p_set_restore_progress(user,imageID, progress):
    ret = False
    logger.info('p_set_restore_progress :%s ' % state)
    g_restore_switch.acquire()
    item = 0
    while item < len(g_restore_transactions):
        if(g_restore_transactions[item].user_name == user and g_restore_transactions[item].image_id == imageID):
            g_restore_transactions[item].progress = progress
            break
        item = item +1
    g_restore_switch.release()
    return True
  
def p_stop_backup_instance(transactionID):
	g_backup_switch.acquire()
	item = 0
	while item<len(g_backup_transactions):
		transaction	= g_backup_transactions[item]			
		if(transaction.transaction_id==transactionID ):
			if transaction.state=='DUPLICATING' :
				OpenLdap.p_stop_backup_instance(transaction.node_ip ,transaction.user_name,transaction.image_id)
			g_backup_transactions.remove(transaction)
			break
		item = item +1    
	g_backup_switch.release()

def p_stop_backup_instance_by_node(nodeIp):
	g_backup_switch.acquire()
	item = 0
	while item<len(g_backup_transactions):
		transaction	= g_backup_transactions[item]			
		if(transaction.node_ip==nodeIp ):
			if transaction.state=='DUPLICATING' :
				OpenLdap.p_stop_backup_instance(transaction.node_ip ,transaction.user_name,transaction.imag_id)
			g_backup_transactions.remove(transaction)
			continue
		item = item +1    
	g_backup_switch.release()
					
def p_create_backup_transcactions(instances):
    if(instances!=None):
        for instance in instances:
            if(instance.user==None or instance.user=='any' or instance.image_id==None or instance.image_id=='any'):
                continue
            is_exisit = False
            g_backup_switch.acquire()
            for transaction in g_backup_transactions:			
                if(transaction.user_name==instance.user and transaction.image_id == instance.image_id):
                    if(transaction.state=='BACKUP_FAILED'):
                        g_backup_transactions.remove(transaction)
                    else:
                        is_exisit = True
                    break
            if not is_exisit:
                bk_transaction = thd_backup_transaction()
                bk_transaction.transaction_id = str(uuid.uuid4())
                bk_transaction.state = 'INIT'
                bk_transaction.user_name = instance.user
                bk_transaction.image_id = instance.image_id
                bk_transaction.machine_name = instance.vm_info.machine_name
                bk_transaction.instance_id = (imageID[4:len(instance.image_id)] + instance.user)[0:15]
                bk_transaction.node_ip = instance.node_ip
                bk_transaction.progress = -1
                g_backup_transactions.append(bk_transaction)
            g_backup_switch.release()
    return True
    
def p_create_restore_transcactions(instances):
    if(instances!=None):
        for instance in instances:
            if(instance.user==None or instance.user=='any' or instance.image_id==None or instance.image_id=='any'):
                continue
            is_exisit = False
            g_restore_switch.acquire()
            for transaction in g_restore_transactions:			
                if(transaction.user_name==instance.user and transaction.image_id == instance.image_id):
                    if transaction.state=='RESTORE_FAILED' or transaction.state=='RESTORE_FINISH':
                        g_restore_transactions.remove(transaction)
                    else:
                        is_exisit = True
                    break
            if not is_exisit:
                bk_transaction = thd_backup_transaction()
                bk_transaction.transaction_id = str(uuid.uuid4())
                bk_transaction.state = 'INIT'
                bk_transaction.user_name = instance.user
                bk_transaction.image_id = instance.image_id
                bk_transaction.machine_name = instance.vm_info.machine_name
                bk_transaction.instance_id = (imageID[4:len(instance.image_id)] + instance.user)[0:15]
                bk_transaction.node_ip = instance.node_ip
                bk_transaction.progress = -1
                g_restore_transactions.append(bk_transaction)
            g_restore_switch.release()
    return True

def p_get_backup_transaction(transactionID):
    bk_transaction = thd_backup_transaction()
    g_backup_switch.acquire()
    for tran in g_backup_transactions:
        if(tran.transaction_id == transactionID):
            bk_transaction.transaction_id = tran.transaction_id
            bk_transaction.state = tran.state
            bk_transaction.user_name = tran.user_name
            bk_transaction.image_id = tran.image_id
            bk_transaction.machine_name = tran.machine_name
            bk_transaction.instance_id = tran.instance_id
            bk_transaction.node_ip = tran.node_ip
            bk_transaction.progress = tran.progress 
            break 
    g_backup_switch.release()            
    return bk_transaction

def p_get_restore_transaction(transactionID):
    bk_transaction = thd_backup_transaction()
    g_restore_switch.acquire()
    for tran in g_restore_transactions:
        if(tran.transaction_id == transactionID):
            bk_transaction.transaction_id = tran.transaction_id
            bk_transaction.state = tran.state
            bk_transaction.user_name = tran.user_name
            bk_transaction.image_id = tran.image_id
            bk_transaction.machine_name = tran.machine_name
            bk_transaction.instance_id = tran.instance_id
            bk_transaction.node_ip = tran.node_ip
            bk_transaction.progress = tran.progress 
            break 
    g_restore_switch.release()            
    return bk_transaction
   
def p_get_all_backup_trans():
    bk_transactions = []
    g_backup_switch.acquire()
    for tran in g_backup_transactions:
        bk_transaction = thd_backup_transaction()
        bk_transaction.transaction_id = tran.transaction_id
        bk_transaction.state = tran.state
        bk_transaction.user_name = tran.user_name
        bk_transaction.image_id = tran.image_id
        bk_transaction.machine_name = tran.machine_name
        bk_transaction.instance_id = tran.instance_id
        bk_transaction.node_ip = tran.node_ip
        bk_transaction.progress = tran.progress
        bk_transactions.append(bk_transaction)
    g_backup_switch.release()
    return bk_transactions
 
def p_get_all_restore_trans():
    bk_transactions = []
    g_restore_switch.acquire()
    for tran in g_restore_transactions:
        bk_transaction = thd_backup_transaction()
        bk_transaction.transaction_id = tran.transaction_id
        bk_transaction.state = tran.state
        bk_transaction.user_name = tran.user_name
        bk_transaction.image_id = tran.image_id
        bk_transaction.machine_name = tran.machine_name
        bk_transaction.instance_id = tran.instance_id
        bk_transaction.node_ip = tran.node_ip
        bk_transaction.progress = tran.progress
        bk_transactions.append(bk_transaction)
    g_restore_switch.release()
    return bk_transactions

def p_is_service_start():
    serviceName = CLOUD_CLC
    return utility.p_is_service_start(serviceName)

def p_start_service():
    serviceName = CLOUD_CLC
    return utility.p_start_service(serviceName)
    
def p_stop_service():
    serviceName = CLOUD_CLC
    logger.info('stop service:%s' % serviceName)
    ret = utility.p_stop_service(serviceName)
    return ret
    
def p_get_migrate_instance_list(userName):
    logger.info('p_get_migrate_instance_list()')
    ins = []
    if g_client_info.has_key(userName) and g_client_info[userName].has_key('remote'):
        clientInfos = g_client_info[userName]['remote'][:]
        for clientInfo in clientInfos:
            if clientInfo.thermophoresis!=None and clientInfo.thermophoresis.is_thermophoresis:
                instance = thd_migrateInfo()
                instance.machinename = clientInfo.vm_info.machine_name
                instance.user = clientInfo.user
                instance.imageId = clientInfo.image_id 
                instance.publicIp = clientInfo.net_info.public_ip
                instance.sourceIP = clientInfo.node_ip
                instance.targetIP = clientInfo.thermophoresis.thermophoresis_node
                trans = OpenLdap.get_instance_transaction_list(clientInfo.node_ip,clientInfo.user)
                for tran in trans:
                    if tran.imageID==clientInfo.image_id:
                        instance.transactionId = tran.transactionID
                        break                
                ins.append(instance)                
    return ins

def p_set_migrage_state(transactionID,state):
    if(transactionID == None ):
        return False
    g_migrate_switch.acquire()
    g_migrate_states[transactionID] = state
    g_migrate_switch.release()
    logger.info("p_set_migrage_state:%d" %state ) 
    return True
      
def p_get_migrage_state(transactionID):
    state = thd_MIGRATESTATE.MIGRATE_FORBIDDEN
    if(transactionID == None ):
        return state
    g_migrate_switch.acquire()
    if(g_migrate_states.has_key(transactionID)):
		state = g_migrate_states[transactionID]   
    else:
        state = thd_MIGRATESTATE.INIT
    g_migrate_switch.release()
    logger.info("p_get_migrage_state:%d"%state) 
    return state

def p_get_migrate_pair_node(nodeIP, user, imageID ):
    list_info = p_get_migrate_instance_list(user)
    pair_node='0.0.0.0'
    for migrateNode in list_info:
        if(migrateNode.sourceIP == nodeIP and migrateNode.imageId == imageID):
            pair_node = migrateNode.targetIP
            break
        elif (migrateNode.targetIP == nodeIP and migrateNode.imageId == imageID):
            pair_node = migrateNode.sourceIP
            break
        else:
            pass
    return pair_node  

# to get the server hard resource    
def p_get_server_resource(serviceId,hostIp):
    hdresource = thd_hard_source()
    return hdresource

# register the service
def p_register_service(serviceName,hostIp, paraName):
    if serviceName=='eucalyptus-nc':
        if paraName==None:
            return -2                  # cluster name cannot be bull
        else:
            ldap_ip = utility.get_ldap_server()
            clusterIp = OpenLdap.p_get_cluster_ip(ldap_ip,paraName)
            if clusterIp!=None:
                OpenLdap.p_register_node(ldap_ip,clusterIp,hostIp)
            else:
                return -5              # the cluster not exist
    else:
        return utility.p_register_service(serviceName,hostIp,paraName)


def p_get_image_by_imageId(imageId):
    img = None
    for image in g_image_list:
        if image.imageId ==imageId:
            img = image
            break
    return img

#when start clc, to init the hard resource info
def p_init_hard_resource():
    ldap_ip = utility.get_ldap_server()
    ipList = OpenLdap.p_get_all_service_ip(ldap_ip)
    for ipAddr in ipList:
        hdResource = thd_service_list()
        hdResource.resource = None
        services = []
        service_id_list = OpenLdap.p_get_services_by_ip(ldap_ip,ipAddr)
        if service_id_list!=None:
            for id in service_id_list:
                servInfo = thd_service()
                servInfo.service_id = id
                servInfo.is_alive = True
                services.append(servInfo)
        hdResource.paas_services = services
        g_resource_clc[ipAddr] = hdResource         
    logger.info('g_resource_clc info %s:' %str(g_resource_clc))    

class p_register_clc_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        p_register_clc()

# add the service to clc services state info
def p_add_sevice_resource(hostIp,serviceId):
    if g_resource_clc.has_key(hostIp):
        hasServ = False
        servs = []
        if g_resource_clc[hostIp]!=None:
            servs = g_resource_clc[hostIp].paas_services
            for serv in servs:
                if serv.service_id==serviceId:
                    hasServ = True
                    break
        if not hasServ:
            clcServ = thd_service()
            clcServ.service_id = serviceId
            clcServ.is_alive = True
            servs.append(clcServ)
            g_resource_switch.acquire()
            g_resource_clc[hostIp].paas_services = servs
            g_resource_switch.release()
    else:
        hdResource = thd_service_list()
        hdResource.resource = None
        servs = []
        clcServ = thd_service()
        clcServ.service_id = thd_SERVICE_TYPE.CLOUD_CLC
        clcServ.is_alive = True
        servs.append(clcServ)
        hdResource.paas_services = servs
        g_resource_switch.acquire()
        g_resource_clc[hostIp] = hdResource 
        g_resource_switch.release() 
    logger.info('p_add_sevice_resource:%s' %str(g_resource_clc))
    return True

#register clc to ldap
def p_register_clc():
    while True:
        clcIp = utility.get_local_publicip()
        if clcIp!=None:
            ldap_ip =  utility.get_ldap_server()   
            clcIpLdap = OpenLdap.get_clc_ip(ldap_ip)
            if clcIpLdap==None or clcIpLdap!=clcIp:
                #p_register_clc: add admin user
                userInfo = thd_UserInfo()                                                             
                userInfo.userName = 'admin'
                userInfo.realName = 'admin'
                m = hashlib.md5()
                m.update('admin')
                userInfo.bCryptedPassword = m.hexdigest()
                userInfo.sSeriesName='default'
                userInfo.popedom = 2 
                logger.info('p_register_clc userInfo: %s' %str(userInfo))             
                addres = OpenLdap.p_add_user(ldap_ip,userInfo)
                if addres:                                                                                                                                                                                                                                                                                                                                                                                                                                                      # register clc to ldap
                    ret = OpenLdap.p_init_clc_info(ldap_ip,clcIp)
                    if ret:
                    #change the clc resource : g_resource_clc                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
                        p_add_sevice_resource(clcIp,thd_SERVICE_TYPE.CLOUD_CLC)
                        break                                                                                                                                                          
            else:
                break
        time.sleep(1)

# to get all vmconfigs  from ldap
def p_get_all_vmconfigs():
    vmConfigs = None
    ldap_ip = utility.get_ldap_server()
    while True:
        time.sleep(2)
        logger.debug('get vmconfigs !')        
        vmConfigs = OpenLdap.get_all_vmConfigs(ldap_ip)
        if vmConfigs==None:
            logger.warn('get vmconfig error!')
        else:
            break
    return vmConfigs

# to get all images  from ldap
def p_get_all_images():
    images = None
    ldap_ip = utility.get_ldap_server()
    while True:
        logger.debug('get all images  !') 
        images = OpenLdap.get_all_images(ldap_ip) 
        if images==None:
            logger.warn('get images error!')
        else:
            break
        time.sleep(2)
    return images

def _init_clc_client_info():
    global g_vmconfig_list
    global g_image_list
    g_vmconfig_list= p_get_all_vmconfigs()
    g_image_list=p_get_all_images()
            
    # create the g_client_info info
    vmEngineData = vm_engine_data()
    vmEngineData.images = g_image_list
    vmEngineData.vmconfigs = g_vmconfig_list
    vmEngineData.nodeList = OpenLdap.get_node_list(utility.get_ldap_server())
    vmEngineData.userList = OpenLdap.get_client_users(utility.get_ldap_server())
    vmConfigEngine.init_client_info(vmEngineData,g_client_info)
    logger.info('the clientdata info %s:' %str(g_client_info))


#when clc start, init the clc global : g_client_info and g_instance_info         
class p_init_vmconfig_image_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self) 
    def run(self):
        logger.info('p_init_vmconfig_image_thread begin')
        p_init_hard_resource()
        _init_clc_client_info()            
                    
def p_get_vmconfig_by_id(vmconfigID):
    vmconfig = None
    for vm in g_vmconfig_list:
        if vm.id == vmconfigID:
            vmconfig = vm
            break
    return vmconfig

#when run instance, if not point node , to dispatch cluster 
def p_dispatch_clusters():
    ldap_ip = utility.get_ldap_server()
    clusters = OpenLdap.get_cluster_list(ldap_ip)
    if clusters!=None and len(clusters)>0:
        return clusters[0].hostIp
    return None

# start the instance
def p_clc_start_vm(clientInfo):
    ret = 0
    if clientInfo==None:
        return -7                     # client info is error
    
    ncIp = None
    ccIp = None
    if clientInfo.is_assign_node:                 #Assign nc mode
        ncIp = clientInfo.node_ip
        ldap_ip = utility.get_ldap_server()
        nodeInfo = OpenLdap.p_get_nodeinfo_by_ip(ldap_ip,ncIp)
        if nodeInfo!=None:  
            ccIp = OpenLdap.p_get_cluster_ip(ldap_ip,nodeInfo.clusterName)
        else:
            ret = -8        # assign node is not exisit
    else:
        ccIp = p_dispatch_clusters()        
    
    if ccIp!=None:
        logger.debug('p_clc_start_vm cc ip:%s' %ccIp)
        retValue = OpenLdap.p_cc_start_vm(ccIp,clientInfo)
        if retValue!=None:
            ret = retValue.return_value
            ncIp = retValue.node_ip
        else:
            ret = -9
    else:
        ret = -9          # can't dispatch cluster   
          
    if ret==0:            # run instance success
        runInstanceData = run_instance_data()
        runInstanceData.user = clientInfo.user
        runInstanceData.image_id = clientInfo.image_id
        runInstanceData.node_ip = ncIp
        nodeList = OpenLdap.get_node_list(utility.get_ldap_server())        
        vmConfigEngine.update_global_by_startvm(runInstanceData,g_image_list,nodeList,g_client_info,g_instance_info)
    
    return ret           

# stop the instance
def p_clc_stop_vm(clientInfo):
    ret = False
    if(g_client_info.has_key(clientInfo.user) and g_client_info[clientInfo.user]!=None):
        for cli in g_client_info[clientInfo.user]['remote']:
            if cli.image_id==clientInfo.image_id:                
                cli.instance_state.state = thd_TRANSACT_STATE.SHUTTING_DOWN
                logger.debug('p_clc_stop_vm client info:%s' %str(g_client_info))
                ret = OpenLdap.p_nc_stop_vm(cli.node_ip,cli)
                break 
    return ret

# to get the client data from clc
def p_get_client_data(user,requestIp):
    clientInfos = []
    logger.info('all client info:%s' %str(g_client_info))

    if user=='super':
        for usrName in g_client_info.keys():
            if g_client_info[usrName].has_key('local'):
                if requestIp!=None and g_client_info[usrName]['local'].has_key(requestIp):
                    localClient = g_client_info[usrName]['local'][requestIp][:]
                    for lcClient in localClient:
                        if lcClient.vm_info.is_clear_power_off:
                            clientInfos.append(lcClient)
    else:
        if g_client_info.has_key(user): 
            if g_client_info[user].has_key('remote'):       # remote node clientdata
                clientInfos = g_client_info[user]['remote'][:]
                for clientInfo in clientInfos:
                    if clientInfo.node_ip!=None and clientInfo.node_ip!='any':
                        if g_resource_clc.has_key(clientInfo.node_ip):
                            p_resource = g_resource_clc[clientInfo.node_ip]
                            servList = p_resource.paas_services
                            hasNc = False
                            for servInfo in servList:
                                if servInfo.service_id == thd_SERVICE_TYPE.CLOUD_NC :
                                    hasNc = True
                                    if not servInfo.is_alive:
                                        clientInfo.instance_state.is_can_run = False
                                    else:
                                        clientInfo.instance_state.is_can_run = True
                                    break
                            if not hasNc:
                                clientInfo.instance_state.is_can_run = False
                        else:
                            clientInfo.instance_state.is_can_run = False
        
            if g_client_info[user].has_key('local') :    # local node clientdata
                if requestIp!=None and g_client_info[user]['local'].has_key(requestIp):
                    localClient = g_client_info[user]['local'][requestIp][:]
                    if localClient!=None:
                        clientInfos.extend(localClient)
    logger.info('user client info:%s' %str(clientInfos))
    return clientInfos

# get the transaction info from cc , to update the clc global   
def p_get_transaction(transmitData):
#    get node transaction , update the clc global : g_client_info and g_instance_info
    global g_client_info
    global g_instance_info
    nodeList = OpenLdap.get_node_list(utility.get_ldap_server())
    vmConfigEngine.update_global_by_transactions(transmitData,nodeList,g_client_info,g_instance_info)
    return True

# get point machine resource    
def p_get_resource(hostIp):
    resourceInfo = thd_service_list()
    p_all_resource = g_resource_clc.copy()
    if p_all_resource.has_key(hostIp):
        resourceInfo = p_all_resource[hostIp]
    logger.info(' p_get_resource info:%s' %str(resourceInfo))
    return resourceInfo
    
# delete the image , to update the clc global
def p_delimg_update_global(imageId):     
    if imageId==None:
        return False
    vmConfigEngine.delete_image(imageId,g_client_info)   
    logger.info(' clientdata info:%s' %str(g_client_info))
    return True

# delete vmconfig,  to update the clc global
def p_delvm_update_global(vmconfigId):
    logger.info(' p_delvm_update_global ')
    vmConfigEngine.delete_vmconfig(vmconfigId,g_client_info)
    logger.info(' p_delvm_update_global clientdata info:%s' %str(g_client_info))
    return True

# change image,  to update the clc global
def p_updateimg_update_global(imageInfo):
    vmConfigEngine.change_image(imageInfo,g_client_info,g_instance_info)
    logger.info(' clientdata info:%s' %str(g_client_info))
    return True    

# change vmconfig,  to update the clc global
def p_updatevm_update_global(vmConfig):
    users = OpenLdap.get_client_users(utility.get_ldap_server())
    nodeList = OpenLdap.get_node_list(utility.get_ldap_server())
    vmConfigEngine.change_vmconfig(vmConfig,g_image_list,nodeList,users,g_client_info)             
    logger.info(' clientdata info:%s' %str(g_client_info))
    return True        

# add image,  to update the clc global
def p_addimg_update_global( imageInfo ):

    return True

# add vmconfig,  to update the clc global
def p_addvm_update_global( vmconfig):
    # update complete ,return true
    if vmconfig!=None and vmconfig.id!=None:
        nodeList = OpenLdap.get_node_list(utility.get_ldap_server())
        users = OpenLdap.get_client_users(utility.get_ldap_server())
        logger.info(' p_addvm_update_global:%s' %str(vmconfig))
        _init_clc_client_info()
#    vmConfigEngine.add_vmconfig(vmconfig,g_image_list,nodeList,users,g_client_info)
    logger.info(' clientdata info:%s' %str(g_client_info))
    return True

def is_vmconfig_used(vmconfig_id):
    is_used = False
    logger.debug('vmconfig_id:%s' %vmconfig_id)
    users = OpenLdap.get_client_users(utility.get_ldap_server())
    for user_info in users:
        if g_client_info.has_key(user_info.userName):
            if g_client_info[user_info.userName].has_key('remote'):
                client_datas = g_client_info[user_info.userName]['remote']
                for client_info in client_datas:
                    logger.debug('client info:%s' %str(client_info))
                    if client_info.vmconfig_id == vmconfig_id and client_info.instance_state.state != thd_TRANSACT_STATE.TERMINATED:
                        is_used = True

            if g_client_info[user_info.userName].has_key('local'):
                for node_ip in g_client_info[user_info.userName]['local'].keys():
                    client_datas = g_client_info[user_info.userName]['local'][node_ip]
                    for client_info in client_datas:
                        if client_info.vmconfig_id == vmconfig_id and client_info.instance_state.state != thd_TRANSACT_STATE.TERMINATED:
                            is_used = True

    return is_used

        
class clcApiHandler:

    def luhya_clc_get_client_data(self , user,requestIp):
        logger.info('luhya_clc_get_client_data user is :%s' %user)
        return p_get_client_data(user,requestIp)
        
    def luhya_clc_start_vm(self ,clientInfo ):	
        return p_clc_start_vm(clientInfo)
        	
    def luhya_clc_stop_vm(self, clientInfo): 
        return p_clc_stop_vm(clientInfo)   

    def luhya_res_clc_run_instance(self, user , imageID, nodeIp):
        ret = -6      
        ncIp = None
        if nodeIp != None:                                   #local nc mode
            ncIp = nodeIp
        else:
            ncIp = p_dispatch_nodes()
        if ncIp!=None:
            imageLen = OpenLdap.p_getImageLength(utility.get_ldap_server(),imageID)
            if imageLen>0:
                transID = OpenLdap.p_create_run_instance_transaction(nodeIp,imageID, imageLen, user,None)
                if transID!=None:
                    ret = OpenLdap.p_runInstance(nodeIp,transID )        
                else:
                    ret = -8
            else:
                ret = -9
        else:
            ret = -10
        return ret
    
    def luhya_res_clc_stop_instance(self, user , imageID, nodeIp):
        return OpenLdap.p_stop_instance(nodeIp,user,imageID)
    
    def luhya_res_clc_restart_instance(self, user , imageID, nodeIp):
        return OpenLdap.p_restart_instance(nodeIp,user,imageID)        
    
    def luhya_res_get_live_instances(self , userName):
        instances = p_get_instance_info_list(userName)
        logger.info('luhya_res_get_live_instances : %s' % str(instances))
        return instances

    def luhya_res_backup_instances(self, instances):     
        return p_create_backup_transcactions(instances)         
        
    def luhya_res_set_backup_state(self, user, imageID, state):
		return p_set_backup_state(user,imageID,state)
		
    def luhya_res_stop_backup_instance(self, transactionID):
        p_stop_backup_instance(transactionID)
        return True
	
    def luhya_res_stop_backup_instance_by_node(self, nodeIp ):
		p_stop_backup_instance_by_node(nodeIp)
		return True
		
    def luhya_res_get_instances_by_node(self , userName , nodeIp):
        ins = []
        ins = p_get_instances_by_node(userName,nodeIp)
        logger.info('luhya_res_get_instances_by_node : %s' % str(ins))
        return ins
		
    def luhya_res_set_backup_progress(self , user,imageID, progress):
	    return p_set_backup_progress(user,imageID, progress)
	  
    def luhya_res_get_all_backup_transactions(self, ):
		return p_get_all_backup_trans()
		
    def luhya_res_get_backup_transaction_by_id(self,transactionID):
		return p_get_backup_transaction(transactionID)	

    def luhya_res_set_restore_state(self , userName,imageID,state):
		return p_set_restore_state(userName,imageID,state)
		
    def luhya_res_set_restore_progress(self , user,imageID, progress):
	    return p_set_restore_progress(user,imageID, progress)

    def luhya_res_get_all_restore_transactions(self, ):
		return p_get_all_restore_trans()	    
	    
    def luhya_res_get_restore_transaction_by_id(self,transactionID):
		return p_get_restore_transaction(transactionID)
		
    def luhya_res_restore_instances(self,instances):
		p_create_restore_transcactions(instances)
		return  True	 
    	
    def luhya_res_clc_get_current_resource(self):     #start booth li
        hdSource = utility.utility_get_current_resource()
        g_source_switch.acquire()
        hdSource.net_receiverate = g_server_resource['recvRate']
        hdSource.net_sendrate = g_server_resource['sendRate']
        hdSource.cpu_utilization = g_server_resource['cpuUtilization']
        g_source_switch.release()
        hdSource.state = 'HW_STATUS_OK'
        if hdSource.cpu_utilization > VM_CPU_UTILIZATION:
            hdSource.state = 'HW_STATUS_WARN'
        logger.info('state:%s,cpuUtilization:%d'% (hdSource.state,hdSource.cpu_utilization))                            
        return hdSource                                       #end booth li
    
	 
		
    def luhya_res_get_migrate_instance_list(self,userName):
        logger.info('luhya_res_get_migrate_instance_list()')
        return p_get_migrate_instance_list(userName)   
        
    def luhya_res_get_migrage_state(self,transactionID):
        logger.info('luhya_res_get_migrage_state %s: ' % transactionID)
        return p_get_migrage_state(transactionID)   
        
    def luhya_res_set_migrage_state(self,transactionID,state):
        logger.info('luhya_res_set_migrage_state %d'%state )
        return p_set_migrage_state(transactionID,state)   
        
    def luhya_res_get_migrate_pair_node(self , nodeIP,user,imageID ):
        logger.info('luhya_res_get_migrate_pair_node() %s: ' % nodeIP)
        return p_get_migrate_pair_node(nodeIP,user,imageID )
        
    def luhya_res_clc_is_service_start(self,):
		return p_is_service_start()

    def luhya_res_clc_start_service(self, ):
        return p_start_service()
        
    def luhya_res_clc_stop_service(self, ):
        return p_stop_service()

    def luhya_res_get_server_resource(self ,serviceId,hostIp):
        return p_get_server_resource(serviceId,hostIp)
    
    def luhya_res_clc_register_service(self, serviceName,hostIp, paraName):
        return p_register_service(serviceName,hostIp, paraName)

    def luhya_res_clc_deregister_service(self,serviceName,parameter):
        return utility.p_deregister_service(serviceName,parameter)

    def luhya_res_transmit_transcation(self, transmitData):
        return p_get_transaction(transmitData)

    def luhya_res_transmit_source(self,IP,hdSource):
        logger.info('luhya_res_transmit_source......')
        ret = False
        if IP != None:
            ret = p_get_hard_source(IP,hdSource)
        return ret
    
    def luhya_res_heart_beat(self,ip,name):
        return p_heart_beat_timer(ip,name)
    
    def luhya_res_nc_heart_beat_dead(self,ncIp,serviceID):
        ret = False
        if ncIp != None:
            ret = p_nc_heart_beat_dead(ncIp,serviceID)
        return ret    
    
    
    def luhya_res_get_resource_by_ip(self, hostIp):
        return p_get_resource(hostIp)
    
    def luhya_res_delimg_update_global(self, imageId):
        return p_delimg_update_global(imageId)
        
    def luhya_res_delvm_update_global(self, vmConfigId):
        return p_delvm_update_global(vmConfigId)
        
    def luhya_res_updateimg_update_global(self, imageInfo):
        return p_updateimg_update_global(imageInfo)
        
    def luhya_res_updatevm_update_global(self, vmconfig):
        return p_updatevm_update_global(vmconfig)
        
    def luhya_res_addimg_update_global(self, imageInfo):
        return p_addimg_update_global(imageInfo)
        
    def luhya_res_addvm_update_global(self, vmconfig):
        return p_addvm_update_global( vmconfig)   
        
    def luhya_res_add_sevice_resource(self, hostIp,serviceId):
        return p_add_sevice_resource(hostIp,serviceId)

    def luhya_res_is_online(self,):
        return True

    def luhya_res_is_vmconfig_used(self, vmconfig_id):
        return is_vmconfig_used(vmconfig_id)

    #set the log level by user
    def luhya_res_set_log_level(self,str_level):
        log_level = logging.WARNING
        if str_level!=None:
            if str_level.upper()=='DEBUG':
                log_level = logging.DEBUG
            elif str_level.upper()=='INFO':
                log_level = logging.INFO
            elif str_level.upper()=='WARNING':
                log_level = logging.WARNING 
            elif str_level.upper()=='ERROR':
                log_level = logging.ERROR
            elif str_level.upper()=='CRITICAL':
                log_level = logging.CRITICAL
        logger.setLevel(log_level)
        return True

    # dump all clc saved info (include: clientinfo \ server info \node info\instance info)
    def luhya_res_dump_clc_data(self ,strData):
        strInfo = ""
        if strData=="clientdata" :       
            client_info = copy.deepcopy(g_client_info)
            strInfo = str(client_info)
        elif strData=="remote-clientdata" :
            client_infos=[]
            for user in g_client_info.keys():
                if g_client_info[user].has_key('remote'):
                    infos = copy.deepcopy(g_client_info[user]['remote'])
                    client_infos.extend(infos)
            strInfo = str(client_infos)
        elif strData=="local-clientdata" :
            client_infos=[]
            for user in g_client_info.keys():
                if g_client_info[user].has_key('local'):
                    infos = copy.deepcopy(g_client_info[user]['local'])
                    client_infos.append(infos)
            strInfo = str(client_infos)
        elif strData=="ncs-info" :
            nodes_info = None
            if g_ldap_ip!=None:
                nodes_info = OpenLdap.get_node_list(g_ldap_ip)
            strInfo = str(nodes_info)
        elif strData=="servers-info" :
            res_info = copy.deepcopy(g_resource_clc)
            strInfo = str(res_info)
        elif strData=="instances-info" :
            ins_info = copy.deepcopy(g_instance_info)
            strInfo = str(ins_info)
        return strInfo


# g_ClcThriftServer_main_interface,ClcThriftServer main interface, starting point 
class g_ClcThriftServer_main_interface(threading.Thread):
    "g_ClcThriftServer_main_interface"
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        logger.info('g_ClcThriftServer_main_interface running ...')
        handler = clcApiHandler()
        processor = clcApi.Processor(handler)
                
        transport = TSocket.TServerSocket(utility.get_local_publicip(),thd_port.THRIFT_CLC_PORT)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        
        #server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
        
        # You could do one of these for a multithreaded server
        #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)
        
        logger.info('Starting the server...')
        server.serve()
        logger.error('thrift server quit!')      




# ClcThriftServerexternal interface
def preInit (user_data):
    logger.info('pre_init starting ...')
    # register clc to ldap
    registerClc = p_register_clc_thread()
    registerClc.start()
    # start the clc server
    ClcThriftServer_main = g_ClcThriftServer_main_interface()
    ClcThriftServer_main.start()
    #get the clc resourceInfo
    getSourceThread = p_get_server_source_thread()
    getSourceThread.start()
    # start the backup  thread    
    backupthread = p_backup_thread()
    backupthread.start()
    # start the restore  thread  
    restorethread = p_restore_thread()
    restorethread.start()
    # to init the clc global : g_client_info and g_instance_info
    init_vm_img_thread = p_init_vmconfig_image_thread()
    init_vm_img_thread.start()
    #to get the clc\ldap\walrus ip
    ip_thread = p_get_ip_thread()
    ip_thread.start()
    #update all services timetramp
    getServThread = p_get_all_services_thread()
    getServThread.start()
    #update all server's hard resource
    hdSourceThread = p_transmit_server_source_thread()
    hdSourceThread.start() 
    #start the clc heartbeat               
    isAliveThread = p_heart_beat_thread()
    isAliveThread.start()    
    
    
    log_string = 'started g_ClcThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string) 
    return 0     #sys.exit()
def postInit (user_data):
  pass
