#!/usr/bin/env python

#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements. See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership. The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.
#

import sys
sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.interface import walrusApi
from cloudbot.interface.ttypes import * 

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

import getopt, sys, os, stat
import shutil
import gzip
import Queue
import threading
import time
import datetime
import tarfile
import gzip
import logging
import string, StringIO
import uuid
import random
import socket
import ldap
from xml.dom.minidom import Document
from xml.dom import minidom
from xml.dom.minidom import parse, parseString
from os import getenv
import commands
import threading
import thread
import statvfs
from cloudbot.utils import OpenLdap,utility     #booth li
from cloudbot.utils.const_def import *

logger = utility.init_log()

g_server_resource = {'recvRate':0,'sendRate':0,'cpuUtilization':0}
g_source_switch = threading.Lock()

g_clc_ip = None
g_wal_ip = None


def p_is_service_start():
  serviceName = CLOUD_WALRUS
  return utility.p_is_service_start(serviceName)

def p_start_service():
  serviceName = CLOUD_WALRUS
  return utility.p_start_service(serviceName)	

def p_stop_service():
  serviceName = CLOUD_WALRUS
  return utility.p_stop_service(serviceName)

def p_heart_beat_timer():
    global g_clc_ip
    global g_wal_ip
    
    if g_clc_ip!=None and g_wal_ip!=None:
        OpenLdap.p_all_heart_beat(g_clc_ip,g_wal_ip,'wal')

    heart = threading.Timer(HEART_BEAT_INTV,p_heart_beat_timer)
    heart.start()

def p_make_dir(strPath):
    ret = False
    if not os.path.exists(strPath):
        try:
            os.makedirs(strPath)
            ret = True
        except:
            ret = False
    else:
        ret = True
    return ret


class p_heart_beat_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_WALRUS,utility.get_local_publicip())
            if ret:
                logger.debug('p_heart_beat_thread start ...')
                p_heart_beat_timer()
                break
            else:
                time.sleep(2)
            
class p_transmit_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.info('p_transmit_server_source_thread...')
        while True:
            if g_wal_ip!=None and g_clc_ip!=None:                        
                hdSource = utility.utility_get_current_resource()
                g_source_switch.acquire()
                hdSource.net_receiverate = g_server_resource['recvRate']
                hdSource.net_sendrate = g_server_resource['sendRate']
                hdSource.cpu_utilization = g_server_resource['cpuUtilization']
                g_source_switch.release()
                hdSource.state = 'HW_STATUS_OK'
                if hdSource.cpu_utilization > VM_CPU_UTILIZATION:
                    hdSource.state = 'HW_STATUS_WARN'            
                OpenLdap.p_transmit_hard_source(g_clc_ip,g_wal_ip,hdSource)
            time.sleep(SERVER_SOURCE_INTV)
            
class p_get_ip_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        while True:
            logger.info('p_get_ip_thread...start')
            global g_clc_ip
            global g_wal_ip
            
            g_wal_ip = utility.get_local_publicip()
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_WALRUS,g_wal_ip)
            if ret:  
                g_clc_ip = OpenLdap.get_clc_ip(ldap_ip)
            if (g_clc_ip != None) and (g_wal_ip != None):
                break
            else:
                logger.info('p_get_ip_thread()')
            time.sleep(1)
            
class p_register_walrus_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            walrusIp = utility.get_local_publicip()
            if walrusIp!=None:
                ldap_ip = utility.get_ldap_server()
                ret = OpenLdap.p_init_walrus_info(ldap_ip,walrusIp)
                if ret:
                    break
            time.sleep(1)                
            

class walrusApiHandler:
  def luhya_res_getImageLength(self, imageID):
    imagesize = -2
    imageFile = IMAGE_DEFAULT_PATH+imageID+'/'+IMAGE_FILE_NAME
    if not os.path.exists(imageFile):
        return -3
    stat = os.stat(imageFile)
    if(stat!=None):
        imagesize = stat.st_size
    return imagesize
    
  def luhya_res_deleteImageFile(self,imageID):
    if(imageID==None):
      return False
    storPath = IMAGE_DEFAULT_PATH+imageID
    if(os.path.exists(storPath)):
      shutil.rmtree(storPath,True)
    return True

  def luhya_res_getFreeDisk(self, ):
    vfs=os.statvfs("/home")
    available=vfs[statvfs.F_BAVAIL]*vfs[statvfs.F_BSIZE]/(1024*1024)
    return  available

  def luhya_res_delete_iso_list(self, isoList):
    if(isoList == None):
		return False
    for isoName in isoList:
        if(isoName == None):
			continue
        isoFile=ISO_FILE_PATH+isoName+'.iso'
        if os.path.isfile(isoFile):
            os.remove(isoFile) 
    return True
				  
  def luhya_res_get_iso_list(self, ):
    isoList=[]
    if not os.path.exists(ISO_FILE_PATH):
        try:
            os.makedirs(ISO_FILE_PATH)
            logger.info(' create path %s ' % ISO_FILE_PATH)
        except:
            logger.error('error: can not create %s ' % ISO_FILE_PATH)
            return None
    filelist = os.listdir(ISO_FILE_PATH) 
    for ln in filelist:
      stat = os.stat(ISO_FILE_PATH+ln)
      if(stat!=None):
        thdFile = thd_file()
        ls=ln.split('.iso')
        thdFile.fileName = ls[0]
        thdFile.createTime = stat.st_ctime
        thdFile.size = stat.st_size
        isoList.append(thdFile)
    return isoList

  def luhya_res_get_p2v_list(self, ):
    p2vList=[]
    if not os.path.exists(P2V_FILE_PATH):
        try:
            os.makedirs(P2V_FILE_PATH)
        except:
            logger.error('error: can not create %s ' % P2V_FILE_PATH)
            return None
    filelist = os.listdir(P2V_FILE_PATH) 
    for ln in filelist:
      stat = os.stat(P2V_FILE_PATH+ln)
      if(stat!=None):
        thdFile = thd_file()
        ls=ln.split('.')
        thdFile.fileName = ls[0]
        thdFile.createTime = stat.st_ctime
        thdFile.size = stat.st_size
        p2vList.append(thdFile)
    return p2vList

  def luhya_res_get_file_length(self , fileName):
    len = -1
    stat = os.stat(fileName)
    if(stat!=None):
        len = stat.st_size
    return len

  def luhya_res_walrus_get_current_resource(self):     #start booth li
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
    return hdSource                                      #end booth li

  def luhya_res_create_dir(self,imagePath):
    return p_make_dir(imagePath) 
 
  def luhya_res_walrus_is_service_start(self,):
    return p_is_service_start()    

  def luhya_res_walrus_start_service(self,):
    return p_start_service()
    
  def luhya_res_walrus_stop_service(self,):
    return p_stop_service() 
   
# g_WalrusThriftServer_main_interface,WalrusThriftServer main interface, starting point 
class g_WalrusThriftServer_main_interface(threading.Thread):
    "g_WalrusThriftServer_main_interface"
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            hostIp = utility.get_local_publicip()
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_WALRUS,hostIp)
            if ret:
                logger.info('g_WalrusThriftServer_main_interface running ...')
                handler = walrusApiHandler()
                processor = walrusApi.Processor(handler)
                
                transport = TSocket.TServerSocket(hostIp,thd_port.THRIFT_WALRUS_PORT)
                tfactory = TTransport.TBufferedTransportFactory()
                pfactory = TBinaryProtocol.TBinaryProtocolFactory()
        
                #server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
        
                # You could do one of these for a multithreaded server
                #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
                server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)
        
                logger.info('Starting the server...')
                server.serve()
                logger.error('thrift server done')
                break
            else:
                time.sleep(2)   

class p_get_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.info('p_get_server_source_thread starting ...')
        while True:            
            recvRate,sendRate = utility.p_get_net_rate()
            cpuUtilization = utility.get_current_cpuUtilization()
            g_source_switch.acquire()
            g_server_resource['recvRate'] = recvRate
            g_server_resource['sendRate'] = sendRate
            g_server_resource['cpuUtilization'] = cpuUtilization
            g_source_switch.release()
            time.sleep(SERVER_SOURCE_INTV)

# WalrusThriftServerexternal interface
def preInit (user_data):
    registerWalrus = p_register_walrus_thread()
    registerWalrus.start()    
    logger.info('pre_init starting ...')
    getSourceThread = p_get_server_source_thread()
    getSourceThread.start()    
    WalrusThriftServer_main = g_WalrusThriftServer_main_interface()
    WalrusThriftServer_main.start() 
    
    ipThread = p_get_ip_thread()
    ipThread.start()
    hdSourceThread = p_transmit_server_source_thread()
    hdSourceThread.start()  
    heartBeatThread = p_heart_beat_thread()
    heartBeatThread.start()
                               
    logger.info('started g_WalrusThriftServer_main_interface pthread,pre_init return.')
    return 0     #sys.exit()

def postInit (user_data):
  pass
