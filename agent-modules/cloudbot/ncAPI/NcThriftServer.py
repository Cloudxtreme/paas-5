#!/usr/bin/env python
# -*- coding: utf-8 -*-
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

import getopt, sys, os, stat
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
import zlib
import zipfile
import os.path
import httplib, urllib
import thread
import commands
import shutil
import hashlib

from xml.dom.minidom import Document
from xml.dom import minidom
from xml.dom.minidom import parse, parseString
from os import getenv

sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.interface import nodeApi
from cloudbot.interface.ttypes import *

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from cloudbot.utils import OpenLdap,utility     #booth li
from cloudbot.utils.const_def import *

g_server_resource = {'recvRate':0,'sendRate':0,'cpuUtilization':0}
g_source_switch = threading.Lock()
g_virsh_command_lock = threading.Lock()

switch = threading.Lock()                   # read and write thread lock
transaction_error = {'error':{}}      # just for fit python rule,aim at product a 'real' file namespace object  
transactions = {} 
euca_transactions = {}                       # the transaction of run instance                                              
transactions['error'] = transaction_error      # init  

g_backup_transaction = {}
g_backup_switch = threading.Lock()

g_restore_transaction = {}
g_restore_switch = threading.Lock()

g_live_migrate_state_lists={}
g_live_migrate_state_switch = threading.Lock()

g_live_vm_lists = {}
g_live_vm_switch = threading.Lock()
g_auto_migrate_state_lists={}
g_auto_migrate_state_switch = threading.Lock()

logger = utility.init_log()
g_clc_ip = None
g_nc_ip = None
g_cc_ip = None


#generate a ramdom instance id by user and imageid
def p_generate_instance_id(user, image_id):
    return (image_id[4:len(image_id)] + user)[0:15]

def p_get_progress(progressfile):
    fh = os.popen ('cat '+progressfile)
    strprog = None
    progress = '-1'
    for ln in fh.readlines ():
        if '%' in ln:
            strprog=ln
    if strprog!=None:
        strlist = strprog.split('%')
        if len(strprog)>1:
            prog = strlist[len(strlist)-2]
            pres = prog.split(' ')
            if len(pres)>0:
                progress = pres[len(pres)-1]
    return progress

def p_get_cc_name_conf():
    ccName = None
    fh = os.popen('cat ' + NC_CONF_FILE)
    for ln in fh.readlines():    
        if 'CC_NAME' in ln:
            ls = ln.rsplit('"')
            ccName = ls[1]
    return ccName

def p_register_node():
    hostIp = utility.get_local_publicip()
    ldap_ip = utility.get_ldap_server()
    logger.debug('p_register_node ldap ip:%s' %ldap_ip)
    while True:
        nodeInfo = OpenLdap.p_get_nodeinfo_by_ip(ldap_ip,hostIp)
        logger.debug('p_register_node node info:%s' %str(nodeInfo))
        if nodeInfo!=None:
            if nodeInfo.clusterName==None :
                ccName = p_get_cc_name_conf()
                logger.debug('p_register_node cc name:%s' %ccName)
                if ccName!=None:
                    node_info = thd_NodeInfo()
                    node_info.clusterName = ccName
                    node_info.hostIp = hostIp
                    node_info.isLocal = False
                    logger.debug('p_register_node node info:%s' %str(node_info))
                    OpenLdap.p_register_node(ldap_ip,node_info)
                else:
                    break
            else:
                break
        time.sleep(1)

class p_register_node_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        p_register_node()


def p_init_backup_tran():
    g_backup_switch.acquire()
    g_backup_transaction['state'] = None
    g_backup_transaction['instanceID'] = None       
    g_backup_transaction['progress'] = -1
    g_backup_transaction['imageID'] = None
    g_backup_transaction['userName'] = None
    g_backup_transaction['threadID'] = None
    g_backup_switch.release()
    g_restore_switch.acquire()
    g_restore_transaction['state'] = None
    g_restore_transaction['instanceID'] = None       
    g_restore_transaction['progress'] = -1
    g_restore_transaction['imageID'] = None
    g_restore_transaction['userName'] = None
    g_restore_transaction['threadID'] = None
    g_restore_switch.release()    

#get Current Time In Seconds, and return with string format
def p_getCurrentTimeInSeconds():
    "p_getCurrentTimeInSeconds"
    return str(int(time.time()))

#p_get_image_vmtype
def p_get_image_vmtype(user,image):
    "p_get_image_vmtype"
    return VM_MEMERY, VM_CPUS


def p_updateModifyTime(transactionID):
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['modifyTime'] = p_getCurrentTimeInSeconds()
    else:
        transaction = {}
        transactions[transactionID]['modifyTime'] = p_getCurrentTimeInSeconds()
        transactions[transactionID] = transaction
    switch.release()
    return 0

# display all instances infomation
def p_display_transactions():
    switch.acquire()
    for tid in transactions.keys():
        if(tid == 'error'):
            pass
        else:
            transaction = transactions[tid]
    switch.release()
    return 0

#create a New CopyOnWrite Image
def p_create_new_copyonwrite_image(newDisk, size):
    cmd_line = 'qemu-img create -f qcow2 TARGET SIZE'
    cmd_line = cmd_line.replace('TARGET', newDisk)
    cmd_line = cmd_line.replace('SIZE', str(size) + 'G')

    logger.info('createNewCopyOnWriteImage : ' + cmd_line)
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)

    if cmd_status:
        logger.error('createNewCopyOnWriteImage cmd_status %s' % str(cmd_status))
        logger.error('createNewCopyOnWriteImage cmd_output %s' % str(cmd_output))
        return -1
    return 0

# prepare CopyOnWrite Image from an original image
def p_prepareCopyOnWriteImage(sourceDisk, targetDisk):
    logger.info('p_prepareCopyOnWriteImage')
    cmd_line = 'qemu-img create -f qcow2 -b SOURCE TARGET'
    cmd_line = cmd_line.replace('SOURCE', sourceDisk)
    cmd_line = cmd_line.replace('TARGET', targetDisk)
    if(os.path.exists(targetDisk)):
        os.remove(targetDisk)
        logger.info('remove %s' % (targetDisk))    	
    log_file = 'p_prepareCopyOnWriteImage : ' + cmd_line
    logger.info(log_file)
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logger.info('p_prepareCopyOnWriteImage cmd_status %s' % str(cmd_status))
    logger.info('p_prepareCopyOnWriteImage cmd_output %s' % str(cmd_output))
    if cmd_status:
        logger.error('p_prepareCopyOnWriteImage  error occur!')
        return -1
    return 0

# generate new instance ID
def p_createInstanceID():
    "p_createInstanceID"
    switch.acquire()
    now = time.time()
    now = int(now)
    now_str = '%x' % now
    InstanceID = 'mke' + '-' + now_str
    switch.release()
    return InstanceID

# get image-making root path
def p_getImageMakingRootPath():
    "p_getImageMakingRootPath"
    root = ''
    ecualyptus_home = os.path.expanduser('~eucalyptus')
    if not ecualyptus_home:
        ecualyptus_home = DEFAULT_EUCA_HOME                       #if user eucalyptus does not exist,use '/var/lib/eucalyptus'
    root = ecualyptus_home + '/.luhya/'
    logger.info('p_getImageMakingRootPath = %s' % (root))
    return root

# get image-Making cache path
def p_getImageMakingCachePath(imageId):
    "p_getImageMakingCachePath"
    path = ''
    path = p_getImageMakingRootPath() + 'caches/' + imageId + '/'
    logger.info('p_getImageMakingCachePath = %s' % (path))
    return path

# get Image-Making Instance Path
def p_getImageMakingInstancePath(user, instanceID):
    "p_getImageMakingInstancePath"
    path = ''
    path = p_getImageMakingRootPath() + 'instances/' + user + '/' + instanceID + '/'
    logger.info('p_getImageMakingInstancePath = %s' % (path))
    return path

#get absolute instance file path with current user and instance ID
def p_getInstanceFile(user, instanceID):
    instancePath = p_getImageMakingInstancePath(user, instanceID)
    return instancePath + DEFAULT_IMAGE_NAME

#get absolute cached image file path with its image ID
def p_getCacheFile(imageID):
    return p_getImageMakingCachePath(imageID) + DEFAULT_IMAGE_NAME

# create spice client connection password
def p_createConnPassword(user_id, n):
    st = user_id
    diff = 0
    for c in (user_id):
        diff = diff + ord(c)
    st=st+str(diff)
    '''for i in range(n + 1):
        st = st.join(['', chr(97 + random.randint(0, 25))])'''
    return st

# get ldap_server from the configure file
def p_get_ldap_server():
    "p_get_ldap_server"
    fh = os.popen('cat /etc/eucalyptus/eucalyptus-ldap.conf')
    setconfig = 1
    for ln in fh.readlines():
        if 'LDAP_SERVER' in ln:
            ln = ln.strip(' \n')
            ls = ln.rsplit('"')
            ldap_server = ls[1]
            setconfig = 0
            break;
    if(setconfig):
        logger.error('p_get_ldap_server error ' )
        return None
    return ldap_server

# get localhost public ip
def p_get_local_publicip():
    "p_get_local_publicip"
    ldapip = p_get_ldap_server()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((ldapip, 80))
    hostip = s.getsockname()[0]
    s.close()
    return hostip

# identify wether a port is tied up by other program
def p_is_port_tieup(port):
    "p_is_port_tieup"
    tieup = False
    localhost = p_get_local_publicip()
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(1)
    try:
        sk.connect((localhost, port))
        tieup = True
    except Exception:
        tieup = False
    sk.close()
    return tieup

# get an available port for spice
# -1: get port error
def p_get_available_port(user,imageId):
    "p_get_available_port"
    port = -1
    baseport = START_PORT
    diffport = 0
    for c in (user+imageId):
        diffport = diffport + ord(c)
    port = baseport + diffport
    if p_is_port_tieup(port): 
        port = port + 1
    '''for i in range(START_PORT, MAX_PORT):
        if not p_is_port_tieup(i):
            port = i
            break'''
    return port

# p_generate_local_para  
def p_generate_local_para(user_id,imageId):
    "p_generate_local_para"
    para = {}
    para['password'] = p_createConnPassword(user_id, 6)
    para['port'] = p_get_available_port(user_id,imageId)
    para['memery'] = VM_MEMERY
    para['vcpus'] = VM_CPUS
    return para


def p_setDefaultNewImageInfo(transactionID, transaction):
    logger.info('p_setDefaultNewImageInfo')
    imageInfo = {}
    imageInfo['imageId'] = None
    imageInfo['imageLocation'] = None
    imageInfo['imageState'] = 'available'
    imageInfo['imageOwnerId'] = None
    imageInfo['architecture'] = 'x86_64'
    imageInfo['imageType'] = 'Desktop'
    imageInfo['kernelId'] = None
    imageInfo['ramdiskId'] = None
    imageInfo['isPublic'] = 1
    imageInfo['signature'] = 'no signature'
    imageInfo['name'] = None
    imageInfo['imageCategory'] = 0
    imageInfo['description'] = 'no description'
    imageInfo['platform'] = 'windows'
    imageInfo['ownerName'] = None
    imageInfo['vmStyle'] = 'm1.small'
    imageInfo['Groups'] = 'not used'
    imageInfo['OS'] = 'windows'
    imageInfo['createTime'] = None
    imageInfo['size'] = 0
    imageInfo['manifest'] = 'not used'
    imageInfo['HYPERVISOR'] = 'kvm'

    if(transaction != None and transaction.newImageInfo != None and transaction.newImageInfo.name != None ):
        imageInfo['name'] = transaction.newImageInfo.name
    if(transaction != None and transaction.platform != None ):
        imageInfo['OS'] = transaction.platform
        imageInfo['platform'] = transaction.platform
    if(transaction != None and transaction.newImageInfo != None and transaction.newImageInfo.imageType != None ):
        imageInfo['imageType'] = transaction.newImageInfo.imageType
    if(transaction != None and transaction.newImageInfo != None and transaction.newImageInfo.vmStyle != None ):
        imageInfo['vmStyle'] = transaction.newImageInfo.vmStyle
    if(transaction != None and transaction.newImageInfo != None ):
        imageInfo['imageCategory'] = transaction.newImageInfo.imageCategory
    if transactions.has_key(transactionID):
        transactions[transactionID]['newImageInfo'] = imageInfo
        return True
    return False


# luhya_res_p_CreateMakeImageTransaction
def p_CreateMakeImageTransaction(imageID, imageLen, user):
    "p_CreateMakeImageTransaction"
    transactionID = uuid.uuid4()
    transactionID = str(transactionID)
    log_file = 'p_CreateMakeImageTransaction:' + transactionID
    logger.info(log_file)
    transactionInfo = {}
    para = p_generate_local_para(user,imageID)
    transactionInfo['transactionID'] = transactionID
    transactionInfo['imageID'] = imageID
    transactionInfo['state'] = thd_TRANSACT_STATE.INIT
    transactionInfo['instanceID'] = p_createInstanceID()
    transactionInfo['instancePort'] = para['port']
    transactionInfo['instancePassword'] = para['password']
    transactionInfo['downloadProgress'] = -1
    transactionInfo['submitTime'] = None
    transactionInfo['submitState'] = None
    transactionInfo['submitProgress'] = -1
    transactionInfo['imageSize'] = imageLen
    transactionInfo['uploadProgress'] = -1
    transactionInfo['uploadSpeed'] = None
    transactionInfo['user'] = user
    transactionInfo['sumbitEstimatedTime'] = None
    transactionInfo['modifyTime'] = p_getCurrentTimeInSeconds()
    transactionInfo['createMode'] = 'IMG'
    transactionInfo['platform'] = 'windows'
    transactionInfo['vmcpu'] = 0
    transactionInfo['vmmemory'] = 0
    transactionInfo['vmdisk'] = 0
    switch.acquire()
    transactions[transactionID] = transactionInfo
    p_setDefaultNewImageInfo(transactionID, None)
    switch.release()
    return transactionID


def p_create_image_transaction(transaction):
    transactionID = uuid.uuid4()
    transactionID = str(transactionID)
    log_file = 'p_create_image_transaction:' + transactionID
    logger.info(log_file)
    transactionInfo = {}
    para = p_generate_local_para(transaction.user,transaction.imageID)
    transactionInfo['transactionID'] = transactionID
    transactionInfo['imageID'] = transaction.imageID
    transactionInfo['state'] = thd_TRANSACT_STATE.INIT
    transactionInfo['instanceID'] = p_createInstanceID()
    transactionInfo['instancePort'] = para['port']
    transactionInfo['instancePassword'] = para['password']
    transactionInfo['downloadProgress'] = -1
    transactionInfo['submitTime'] = None
    transactionInfo['submitState'] = None
    transactionInfo['submitProgress'] = -1
    transactionInfo['imageSize'] = transaction.imageSize
    transactionInfo['uploadProgress'] = -1
    transactionInfo['uploadSpeed'] = None
    transactionInfo['user'] = transaction.user
    transactionInfo['sumbitEstimatedTime'] = None
    transactionInfo['modifyTime'] = p_getCurrentTimeInSeconds()
    transactionInfo['bootFrom'] = 'cdrom'
    if(transaction.createMode != None):
        transactionInfo['createMode'] = transaction.createMode
    else:
        transactionInfo['createMode'] = 'IMG'
    if (cmp(transaction.createMode, 'ISO') == 0):
        transactionInfo['imageSize'] = OpenLdap.get_walrus_file_length(utility.get_ldap_server(),ISO_FILE_PATH + transaction.imageID + '.' + ISO_EXTERN_NAME)
        transactionInfo['platform'] = transaction.platform
        transactionInfo['vmcpu'] = transaction.vmcpu
        transactionInfo['vmmemory'] = transaction.vmmemory
        transactionInfo['vmdisk'] = transaction.vmdisk
    if (cmp(transaction.createMode, 'P2V') == 0):
        transactionInfo['imageSize'] = OpenLdap.get_walrus_file_length(utility.get_ldap_server(),P2V_FILE_PATH + transaction.imageID)
        transactionInfo['platform'] = transaction.platform
        transactionInfo['vmcpu'] = transaction.vmcpu
        transactionInfo['vmmemory'] = transaction.vmmemory
        transactionInfo['vmdisk'] = transaction.vmdisk
    
    switch.acquire()
    transactions[transactionID] = transactionInfo
    p_setDefaultNewImageInfo(transactionID, transaction)
    switch.release()
    logger.info('p_create_image_transaction:'+transactionID)
    return transactionID

# create transaction , add the vmconfig id
def p_create_run_instance_transaction(clientData):
    if clientData == None:
        logger.error('no client data')
        return None
    
    user = clientData.user
    imageID = clientData.image_id
    
    transactionID = uuid.uuid4()
    transactionID = str(transactionID)
    transactionInfo = {}
    transactionInfo['transactionID'] = transactionID
    transactionInfo['imageID'] = imageID
    transactionInfo['state'] = thd_TRANSACT_STATE.INIT
    transactionInfo['instanceID'] = p_generate_instance_id(user, imageID)
    transactionInfo['instancePort'] = p_get_available_port(user,imageID)
    transactionInfo['instancePassword'] = p_createConnPassword(user, 6)
    transactionInfo['downloadProgress'] = -1
    transactionInfo['imageSize'] = clientData.image_size
    transactionInfo['user'] = user
    transactionInfo['nodeIp'] = clientData.node_ip
    transactionInfo['modifyTime'] = str(int(time.time()))
    transactionInfo['clientData'] = clientData
    switch.acquire()
    euca_transactions[transactionID] = transactionInfo
    switch.release()
    logger.info('p_create_run_instance_transaction: %s' % str(transactionInfo))
    return transactionID


def p_extract(file, dir):
    if not dir.endswith(':') and not os.path.exists(dir):
        os.mkdir(dir)
    zf = zipfile.ZipFile(file)
    dirs = []
    for name in zf.namelist():
        if name.endswith('/'):
            dirs.append(name)
    dirs.sort()
    for zipdir in dirs:
        curdir = os.path.join(dir, zipdir)
        if not os.path.exists(curdir):
            os.mkdir(curdir)

    num_files = len(zf.namelist())
    for i, name in enumerate(zf.namelist()):
        if not name.endswith('/'):
            outfile = open(os.path.join(dir, name), 'wb')
            outfile.write(zf.read(name))
            outfile.flush()
            outfile.close()
    return


def p_getcredential(user, savePath):
    cred = False
    clcIp = g_clc_ip
    if clcIp!=None:
        ldap_ip =  utility.get_ldap_server()   
        certificateCode = OpenLdap.get_certificate_Code(ldap_ip,  user)
        if certificateCode!=None:
            url = "https://" + clcIp + ":8443/getX509?user=" + user + "&keyValue=" + user + "&code=" + certificateCode
            logger.info('p_getcredential url: %s' % (url))
            zipFile = savePath + "/" + user + ".zip"
            logger.info('p_getcredential zipFile: %s' % (zipFile))
            try:                
                crethttp = urllib.URLopener()
                crethttp.retrieve(url, zipFile)
                if os.path.exists(zipFile):
                    p_extract(zipFile, savePath)
                    cred = True
            except:
                cred = False
    return cred

class p_get_global_ip_intv_thread(threading.Thread):
    def __init__(self):
            threading.Thread.__init__(self)    
    def run(self):    
        while True:
            logger.info('p_get_global_ip_intv_thread ..... start')
            global g_clc_ip
            global g_nc_ip
            global g_cc_ip
            
            g_nc_ip = utility.get_local_publicip()
            logger.info('p_get_global_ip_intv_thread ..... g_nc_ip:%s' %g_nc_ip)
            if g_nc_ip != None:
                ldap_ip = utility.get_ldap_server()
                ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_NC,g_nc_ip)
                if ret:
                    ldap_ip =  utility.get_ldap_server()   
                    g_clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                    logger.info('p_get_global_ip_intv_thread ..... g_clc_ip:%s' %g_clc_ip)
                    if ldap_ip!=None and g_nc_ip!=None:
                        nodeInfo = OpenLdap.p_get_nodeinfo_by_ip(ldap_ip,g_nc_ip)
                        logger.info('p_get_global_ip_intv_thread ..... nodeinfo:%s' %str(nodeInfo))
                        if nodeInfo != None and nodeInfo.clusterName!=None:
                            g_cc_ip = OpenLdap.p_get_cluster_ip(ldap_ip,nodeInfo.clusterName)
                            logger.info('p_get_global_ip_intv_thread ..... g_cc_ip:%s' %g_cc_ip)
            if (g_nc_ip != None) and (g_clc_ip != None) and (g_cc_ip != None):
                logger.info('g_nc_ip:%s,g_clc_ip:%s,g_cc_ip:%s' %(g_nc_ip,g_clc_ip,g_cc_ip))
                ldap_ip = utility.get_ldap_server()
                intv = OpenLdap.p_get_ins_report_intv(ldap_ip)
                if intv!=None and len(intv)>0:
                    global INSTANCE_REPORT_INTV
                    INSTANCE_REPORT_INTV = int(intv)
                break
            logger.info('waiting in p_get_global_ip_intv_thread()!!!')
            time.sleep(1)

class p_transmit_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('p_transmit_server_source_thread...')
        while True:
            time.sleep(SERVER_SOURCE_INTV)            
            hdSource = utility.utility_get_current_resource()
            g_source_switch.acquire()
            hdSource.netReceiveRate = g_server_resource['recvRate']
            hdSource.netSendRate = g_server_resource['sendRate']
            hdSource.cpuUtilization = g_server_resource['cpuUtilization']
            g_source_switch.release()
            hdSource.state = 'VM_STATUS_RIGHT'
            if hdSource.cpuUtilization > VM_CPU_UTILIZATION:
                hdSource.state = 'VM_STATUS_WARN'
            if g_cc_ip!=None and g_nc_ip!=None:    
                OpenLdap.p_transmit_cluster_source(g_cc_ip,g_nc_ip,hdSource)


class p_downloadBaseImageThread(threading.Thread):
    def __init__(self, imageId, imageLen):
        threading.Thread.__init__(self)
        self.imageId = imageId
        self.imageLen = imageLen

    def run(self):
        logger.info('p_downloadBaseImageDigest_job starting ...')
        ret = p_downloadBaseImageThread_job(self.imageId, self.imageLen)
        if(ret):
            logger.error('p_downloadBaseImageThread run error!')
            pass

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
            logger.debug('p_get_server_source_thread: recvRate:%dB/S,sendRate:%dB/S,cpuUtilization:%d'%(recvRate,sendRate,cpuUtilization))
            time.sleep(SERVER_SOURCE_INTV)


class p_download_iso_file(threading.Thread):
    def __init__(self, isoFile, isoLen, isoPath):
        threading.Thread.__init__(self)
        self.isoFile = isoFile
        self.isoLen = isoLen
        self.isoPath = isoPath

    def run(self):
        logger.info('p_download_iso_file starting ...')
        ret = p_download_iso_thread_job(self.isoFile, self.isoLen, self.isoPath)
        if(ret):
            logger.error('p_download_iso_file run error!')
            pass

class p_download_p2v_file(threading.Thread):
    def __init__(self, transactionID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID

    def run(self):
        logger.info('p_download_p2v_file starting ...')
        ret = p_download_p2v_thread_job(self.transactionID)
        if(ret):
            logger.error('p_download_p2v_file run error!')
            pass

def p_getImageLength(ImageDigestFile):
    "p_getImageLength"
    imagesize = -1
    if ImageDigestFile != None:
        if not os.path.exists(ImageDigestFile):
            logger.error('error: %s not exist' % (ImageDigestFile))
            return -1
        dom = parse(ImageDigestFile)
        manifest_element = dom.getElementsByTagName('manifest')[0]
        image_element = manifest_element.getElementsByTagName('image')[0]
        size_element = image_element.getElementsByTagName('size')[0]
        node = size_element.childNodes[0]
        imagesize = int(node.nodeValue)
    logger.info('p_getImageLength = %d' % (imagesize))
    return imagesize


def p_downloadBaseImageDigestThread_job(imageId):
    '''cmd_getdecryptes = 'Wclient GetObject -h HOST_IP:PORT -m IMAGELOCATION -f MACHINE -r CERTPEM -k PKPEM'
    imageLocation = OpenLdap.get_image_location(imageId)

    if imageLocation == None:
        logger.error('error:can not get Image %s Location' % (imageId))
        return -1'''
    cmd_line='wget -c -t 30 HOST_IP/storage/images/IMAGE_ID/IMAGE_NAME -O DEST_FILE';
    ldap_ip =  utility.get_ldap_server()       
    hostip, port = OpenLdap.get_walrus_info(ldap_ip)
    if hostip == None:
        logger.error('error:can not get walrus IP address')
        return -1
    '''if port == None:
        logger.error('error:can not get walrus port')
        return -1'''

    machine_path = p_getImageMakingCachePath(imageId)
    if machine_path == None:
        logger.error('error:can not get image-making cache path')
        return -1

    if not os.path.exists(machine_path):
        try:
            os.makedirs(machine_path)
        except:
            logger.error('error: can not create %s ' % machine_path)
            return -1

    machine_file = machine_path + DEFAULT_IMAGE_NAME + '.digest'
    if os.path.exists(machine_file):
        os.remove(machine_file)
        logger.info('remove %s' % (machine_file))
    '''euca_home = getenv('EUCALYPTUS')
    if euca_home:
        cert_pem_file = euca_home + '/var/lib/eucalyptus/keys/node-cert.pem'
        pk_pem_file = euca_home + '/var/lib/eucalyptus/keys/node-pk.pem'
    else:
        cert_pem_file = '/var/lib/eucalyptus/keys/node-cert.pem'
        pk_pem_file = '/var/lib/eucalyptus/keys/node-pk.pem'
    cmd_getdecryptes = cmd_getdecryptes.replace('HOST_IP', hostip)
    cmd_getdecryptes = cmd_getdecryptes.replace('PORT', port)
    cmd_getdecryptes = cmd_getdecryptes.replace('IMAGELOCATION', imageLocation)
    cmd_getdecryptes = cmd_getdecryptes.replace('MACHINE', machine_file)
    cmd_getdecryptes = cmd_getdecryptes.replace('CERTPEM', cert_pem_file)
    cmd_getdecryptes = cmd_getdecryptes.replace('PKPEM', pk_pem_file)'''

    cmd_line = cmd_line.replace('HOST_IP', hostip)
    cmd_line = cmd_line.replace('IMAGE_ID', imageId)
    cmd_line = cmd_line.replace('IMAGE_NAME', DEFAULT_IMAGE_NAME)
    cmd_line = cmd_line.replace('DEST_FILE', machine_file)
    
    logger.info('cmd_line: %s' % (cmd_line))
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logger.info('cmd_status:%s ' % str(cmd_status))
    logger.info('cmd_output %s ' % str(cmd_output))
    if cmd_status:
        logger.error('p_downloadBaseImageDigestThread_job getstatusoutput error')
        return -1
    return 0


def p_scp_from_remote_host(user, password, remotehost, remotefile, localpath):
    src = user + "@" + remotehost + ":" + remotefile
    dst = localpath
    copy_cmd = "scp " + src + " " + dst
    logger.info('cmd_output %s ' % copy_cmd)
    ssh_newkey = "Are you sure you want to continue connecting"
    p = pexpect.spawn(copy_cmd, timeout=None)
    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline(password)
        p.expect(pexpect.EOF)
    elif i == 2:
        logger.info("I either got key or connection timeout")
        return -1
    return 0


def p_download_iso_thread_job(isoFile, isoLen,isoPath):
    ldap_ip =  utility.get_ldap_server()       
    hostip, port = OpenLdap.get_walrus_info(ldap_ip)
    if(hostip == None):
        return -1
    cmd_file = 'touch '+'NULL>'+isoPath+'progress.log'
    logger.info('iso_path:%s' %cmd_file)
    commands.getstatusoutput(cmd_file)
    cmd = 'rsync -a --progress --bwlimit=6144 ' + hostip + ':' + isoFile + ' ' + isoFile + ' >' +isoPath+'progress.log'
    cmd_status, cmd_output = commands.getstatusoutput(cmd)
    logger.info('p_download_iso_thread_job cmd_output:%s' % str(cmd_output))
    if cmd_status:
        logger.error('p_download_iso_thread_job get status output error')
        return -1
    return 0

def p_download_p2v_thread_job(transcationID):
    transcation = p_getTransactionStatus(transcationID)
    ldap_ip =  utility.get_ldap_server()           
    hostip, port = OpenLdap.get_walrus_info(ldap_ip)
    if(hostip == None):
        return -1
    p2vFileSrc = P2V_FILE_PATH + transcation['imageID']
    isoPath = p_getImageMakingCachePath(P2V_PATH_PREFIX+transcation['imageID'])
    p2vFileDec = isoPath + DEFAULT_IMAGE_NAME
    cmd_file = 'touch '+'NULL>'+isoPath+'progress.log'
    commands.getstatusoutput(cmd_file)
    cmd = 'rsync -a --progress --bwlimit=6144 '+ hostip + ':' + p2vFileSrc + ' ' + p2vFileDec + ' >'+isoPath+'progress.log'
    cmd_status, cmd_output = commands.getstatusoutput(cmd)
    logger.info('p_download_p2v_thread_job cmd_output:%s' % str(cmd_output))
    if cmd_status:
        logger.error('p_download_p2v_thread_job get status output error')
        return -1
    return 0

# vrun main command job
def p_downloadBaseImageThread_job(imageId, imageLen):
    logger.info("p_downloadBaseImageThread_job")
    cmd_line='wget -c -t 30 --limit-rate=5120k http://HOST_IP/storage/images/IMAGE_ID/IMAGE_NAME -O DEST_FILE';
    
    ldap_ip =  utility.get_ldap_server()       
    hostip, port = OpenLdap.get_walrus_info(ldap_ip)
    if hostip == None:
        logger.error('error:can not get walrus IP address')
        return -1

    machine_path = p_getImageMakingCachePath(imageId)
    if machine_path == None:
        logger.error('error:can not get image-making cache path')
        return -1

    if not os.path.exists(machine_path):
        try:
            os.makedirs(machine_path)
        except:
            logger.error('error: can not create %s ' % machine_path)
            return -1
    machine_file = machine_path + DEFAULT_IMAGE_NAME
    if os.path.exists(machine_file):
        iLen = os.path.getsize(machine_file)
        if(iLen > imageLen):
            #the error image file should be deleted
            os.remove(machine_file)
            logger.info('remove file %s' % (machine_file))

    cmd_line = cmd_line.replace('HOST_IP', hostip)
    cmd_line = cmd_line.replace('IMAGE_ID', imageId)
    cmd_line = cmd_line.replace('IMAGE_NAME', DEFAULT_IMAGE_NAME)
    cmd_line = cmd_line.replace('DEST_FILE', machine_file)
        
    logger.info('cmd_line: %s' % (cmd_line))
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logger.info('p_downloadBaseImageThread_job cmd_status:%s' % str(cmd_status))
    logger.info('p_downloadBaseImageThread_job cmd_output:%s' % str(cmd_output))
    if cmd_status:
        logger.error('p_downloadBaseImageThread_job download error')
        return -1
   
    cmd_line = 'sudo chown eucalyptus:eucalyptus '+machine_file
    logger.info('cmd_line: %s' % (cmd_line))
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    if cmd_status:
        logger.error('p_downloadBaseImageThread_job chown error')
        return -1
    return 0

#get transaction according transactionID
def p_getTransactionStatus(transactionID):
    "p_getTransactionStatus"
    transaction = None
    if transactionID != None:
        if transactions.has_key(transactionID):
            transaction = transactions[transactionID]
    logger.info('p_getTransactionStatus: %s' % str(transaction))
    return transaction


def p_euca_get_transaction(transactionID):
    transaction = None
    if transactionID != None:
        if euca_transactions.has_key(transactionID):
            transaction = euca_transactions[transactionID]
    logger.info('p_euca_get_transaction: %s' % str(transaction))
    return transaction


def p_getInstanceFileSize(user, instanceID):
    instanceSize = 0;
    instancefile = p_getInstanceFile(user, instanceID)
    if os.path.exists(instancefile):
        instanceSize = os.path.getsize(instancefile)
    return instanceSize

# p_isImageExist
def p_isImageExist(ncInsCachePath, imageLen):
    "p_isImageExist"
    image_root = ncInsCachePath
    if not os.path.exists(image_root):
        logger.error('p_isImageExist: image path not exsist !' )
        return False
    image_path = image_root + DEFAULT_IMAGE_NAME
    if not os.path.isfile(image_path):
        logger.error('p_isImageExist: image not exsist !' )
        return False
    getsize = os.path.getsize(image_path)
    if getsize != imageLen:
        logger.error('p_isImageExist: image length not corect !' )
        return False
    return True

# p_updateTransactionState  
def p_updateTransactionState(state_name, transactionID):
    "p_updateTransactionState"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['state'] = state_name
    else:
        transaction = {}
        transaction['state'] = state_name
        transactions[transactionID] = transaction
    switch.release()
    return 0


def p_euca_update_transaction_state(state_name, transactionID):
    switch.acquire()
    if euca_transactions.has_key(transactionID):
        euca_transactions[transactionID]['state'] = state_name
    switch.release()
    return 0


# p_update_downloadProgress
def p_update_downloadProgress(downloadProgress, transactionID):
    "p_update_downloadProgress"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['downloadProgress'] = downloadProgress
    else:
        transaction = {}
        transaction['downloadProgress'] = downloadProgress
        transactions[transactionID] = transaction
    switch.release()
    return 0


def p_euca_update_downloadProgress(downloadProgress, transactionID):
    switch.acquire()
    if euca_transactions.has_key(transactionID):
        euca_transactions[transactionID]['downloadProgress'] = downloadProgress
    switch.release()
    return 0

# p_get_image_download_state
def p_get_image_download_state(imageID, imageLen):
    "p_get_image_download_state"
    if imageLen <= 0:
        logger.error('p_get_image_download_state: image len not corect !' )
        return -1
    image_root = p_getImageMakingCachePath(imageID)
    if image_root == None:
        logger.error('p_get_image_download_state: image path not corect !' )
        return -1
    if not os.path.exists(image_root):
        os.makedirs(image_root)
    image_path = image_root + DEFAULT_IMAGE_NAME
    if not os.path.isfile(image_path):
        logger.error('p_get_image_download_state: image file not corect !' )
        return -1
    getsize = os.path.getsize(image_path)
    logger.info('p_get_image_download_state imagelen = %d currentLen = %d' % (imageLen, getsize))

    getsize = getsize * 100
    range = 0
    try:
        range = getsize / imageLen
    except:
        #log math error
        return -1

    range = int(range)
    return range


def p_download_image(transaction):
    res = -1
    if (transaction['state'] == thd_TRANSACT_STATE.INIT) or (
    transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED) or (
    transaction['state'] == thd_TRANSACT_STATE.TERMINATED) or (transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED):
        haveError = False
        isDownloadFinished = False
        imageID = transaction['imageID']
        transactionID = transaction['transactionID']
        #get and create image cache path
        ncInsCachePath = p_getImageMakingCachePath(
            imageID)                          # get Make Image Instance Cache Path
        if not os.path.exists(ncInsCachePath):
            try:
                os.makedirs(ncInsCachePath)
            except:
                loggging.error('Create ' + ncInsCachePath + ' error!')
                return -1
        logger.info('the cache path is: %s' % (ncInsCachePath))
        #get base image size
        imageLen = transaction['imageSize']
        #cache base image
        isExist = p_isImageExist(ncInsCachePath, imageLen)
        if isExist == False:
            logger.info('image not cached, begin to download image %s' % (imageID))
            p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOADING, transactionID)
            isOtherDownloading = False
            switch.acquire()
            for tid in transactions.keys():
                if(tid != 'error'):
                    trans = transactions[tid]
                    if(trans['imageID'] == imageID):
                        if(trans['downloadProgress'] >= 0 and trans['downloadProgress'] < 100):
                            isOtherDownloading = True
                            break
            switch.release()

            if(not isOtherDownloading):
                logger.info('downloading the image %s' % (imageID))
                processid = p_downloadBaseImageThread(imageID, imageLen)
                processid.start()

            downloadProgress_pre = 0
            p_update_downloadProgress(downloadProgress_pre, transactionID)
            times = 0
            while  True:
                time.sleep(2)
                downloadProgress = p_get_image_download_state(imageID, imageLen)
                logger.info('download progress %d' % (downloadProgress))
                if downloadProgress > 100:
                    isDownloadFinished = False
                    haveError = True
                    break
                if downloadProgress == 100:
                    isDownloadFinished = True
                    break
                if downloadProgress_pre == downloadProgress:
                    times = times + 1
                else:
                    times = 0

                if times > MAXTIMES:
                    haveError = True;
                    break;
                downloadProgress_pre = downloadProgress
                if(downloadProgress_pre >= 0):
                    p_update_downloadProgress(downloadProgress_pre, transactionID)
            if haveError:
                p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                p_update_downloadProgress(-1, transactionID)
                processid.stop()
        logger.info('end of image download')
        if(isExist or isDownloadFinished ):
            res = 0
    return res


def p_prepare_iso_image(transaction):
    res = -1
    if (transaction['state'] == thd_TRANSACT_STATE.INIT) or (
    transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED) or (
    transaction['state'] == thd_TRANSACT_STATE.TERMINATED) or (transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED):
        transactionID = transaction['transactionID']
        if not os.path.exists(ISO_FILE_PATH):
            try:
                os.makedirs(ISO_FILE_PATH)
            except:
                logger.error('Create ' + ISO_FILE_PATH + ' error!')
                p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
                return -1
        isoFile = ISO_FILE_PATH + transaction['imageID'] + '.' + ISO_EXTERN_NAME
        isoLen = transaction['imageSize']
        p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOADING, transactionID)
        isoExisit = False
        if os.path.exists(isoFile):
            stat = os.stat(isoFile)
            if(stat!=None):
                if isoLen == stat.st_size :
                    isoExisit=True           
        if(not os.path.exists(isoFile) or transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED ):
            processid = p_download_iso_file(isoFile, isoLen,ISO_FILE_PATH)       # scp the iso file from walrus
            processid.start()
        
        downloadProgress_pre = 0
        haveError = False
        isDownloadFinished = False
        p_update_downloadProgress(downloadProgress_pre, transactionID)
        times = 0
        logfile = ISO_FILE_PATH + 'progress.log'
        if not isoExisit:
            while  True:
                time.sleep(2)
                downloadProgress = int(p_get_progress(logfile))            # get copy iso file progress
                logger.info('iso download progress %d' % (downloadProgress))
                if downloadProgress > 100:
                    isDownloadFinished = False
                    haveError = True
                    break
                if downloadProgress == 100:
                    isDownloadFinished = True
                    break
                if downloadProgress_pre == downloadProgress:
                    times = times + 1
                else:
                    times = 0

                if times > MAXTIMES:
                    haveError = True;
                    break;
                downloadProgress_pre = downloadProgress
                p_update_downloadProgress(downloadProgress_pre, transactionID)
            if haveError:
                p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                p_update_downloadProgress(-1, transactionID)
                processid.stop()
                res = -1
        else:
            isDownloadFinished=True
        if(isDownloadFinished):
            logger.info('iso download progress finished')
            p_update_downloadProgress(100, transactionID)
            res = 0
    return res


def p_prepare_p2v_image(transaction):
    logger.info('p_prepare_p2v_image')
    res = -1
    if (transaction['state'] == thd_TRANSACT_STATE.INIT) or (
    transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED) or (
    transaction['state'] == thd_TRANSACT_STATE.TERMINATED) or (transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED):
        transactionID = transaction['transactionID']
        p2vMachine = P2V_PATH_PREFIX + transaction['imageID']
        logger.info('p_prepare_p2v_image p2v file is: %s' % (p2vMachine))
        p2vCachePath = p_getImageMakingCachePath( p2vMachine)
        if not os.path.exists(p2vCachePath):
            try:
                os.makedirs(p2vCachePath)
            except:
                logger.error('Create ' + p2vCachePath + ' error!')
                p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
                return -1
        p2vFile = p_getCacheFile(p2vMachine)
        p2vLen = transaction['imageSize']
        p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOADING, transactionID)
        if(not os.path.exists(p2vFile) or transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED ):
            processid = p_download_p2v_file(transactionID)       # scp the iso file from walrus
            processid.start()
        downloadProgress_pre = 0
        haveError = False
        isDownloadFinished = False
        p_update_downloadProgress(downloadProgress_pre, transactionID)
        times = 0
        logfile = p2vCachePath + 'progress.log'
        while  True:
            time.sleep(2)
            downloadProgress = int(p_get_progress(logfile))             # get copy iso file progress
            logger.info('p2v download progress %d' % (downloadProgress))
            if downloadProgress > 100:
                isDownloadFinished = False
                haveError = True
                break
            if downloadProgress == 100:
                isDownloadFinished = True
                break
            if downloadProgress_pre == downloadProgress:
                times = times + 1
            else:
                times = 0

            if times > MAXTIMES:
                haveError = True;
                break;
            downloadProgress_pre = downloadProgress
            p_update_downloadProgress(downloadProgress_pre, transactionID)
        if haveError:
            p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
            p_update_downloadProgress(-1, transactionID)
            processid.stop()
            res = -1

        if(isDownloadFinished):
            logger.info('p2v file download progress finished')
            p_update_downloadProgress(100, transactionID)
            res = 0
    return res


# p_runInstanceByBaseImageThread_job
def p_runInstanceByBaseImageThread_job(transactionID):
    "p_runInstanceByBaseImageThread_job"
    transaction = p_getTransactionStatus(
        transactionID)                                       # get transaction according transactionID
    if transaction == None:                                                                   # instance id not exist
        logger.error('can not find transaction ' + transactionID)
        return -1
    else:
        p_updateModifyTime(transactionID)
        user = transaction['user']
        imageID = transaction['imageID']
        instanceID = transaction['instanceID']
        if(cmp(transaction['createMode'], 'IMG') == 0):
            downRes = p_download_image(transaction)                            # get the image from walrus
            if (downRes == 0):
                p_update_downloadProgress(100, transactionID)
                p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FINISHED, transactionID)
                runThread = p_runInstanceThread(transactionID, user, imageID)
                runThread.start()
            else:
                return downRes

        if(cmp(transaction['createMode'], 'ISO') == 0):
            # get the iso file from walrus
            needCreateQcow = False
            if(transaction['state'] == thd_TRANSACT_STATE.INIT) or (
            transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED):
                needCreateQcow = True
            downRes = p_prepare_iso_image(transaction)
            logger.info('p_prepare_iso_image  over downRes:%d ' % (downRes))
            # create new copy on write image
            if(downRes == 0):
                isoMachineRoot = p_getImageMakingInstancePath(user, instanceID)
                logger.info('isoMachineRoot :%s ' % (isoMachineRoot))
                if not os.path.exists(isoMachineRoot):
                    try:
                        os.makedirs(isoMachineRoot)
                    except:
                        p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                        loggging.error('Create ' + isoMachineRoot + ' error!')
                        return -1

                #download successfully, then create new qcow2 image

                if (needCreateQcow):
                    downRes = p_create_new_copyonwrite_image(p_getInstanceFile(user, instanceID), transaction['vmdisk'])

                logger.info('p_runInstanceByBaseImageThread_job update DOWNLOAD_FINISHED the state: %d ' % downRes)
                #run instance from iso image
                if(downRes == 0):
                    isoMachine = ISO_PAIH_PREFIX + imageID
                    p_update_downloadProgress(100, transactionID)
                    p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FINISHED, transactionID)
                    logger.info('p_runInstanceByBaseImageThread_job iso file update DOWNLOAD_FINISHED ')
                    runThread = p_runInstanceThread(transactionID, user, isoMachine)
                    runThread.start()
                else:
                    p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                    return downRes
            else:
                return downRes

        if(cmp(transaction['createMode'], 'P2V') == 0):
            # get the p2v file from walrus
            downRes = p_prepare_p2v_image(transaction)
            if(downRes == 0):
                p_update_downloadProgress(100, transactionID)
                p2vMachine = P2V_PATH_PREFIX + imageID
                p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FINISHED, transactionID)
                logger.info('p_runInstanceByBaseImageThread_job update p2v Machine file DOWNLOAD_FINISHED ')
                runThread = p_runInstanceThread(transactionID, user, p2vMachine)
                runThread.start()
            else:
                p_updateTransactionState(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                return downRes

    return 0

def p_write_file(file,str):
    ret = False
    if(os.path.exists(file)):
        os.remove(file)    
    pf = open ( file, 'w' )
    if pf!=None:
        pf.write ( str )
        pf.close()
        ret = True
    return ret

# startVM
def p_startVM(vmID,vmAttributes):
    "startVM"
    logger.info("startVM with:")
    logger.info(vmAttributes)
    ret = -1
    vmConfFile = '/tmp/'+vmID+'.xml'
    if p_write_file(vmConfFile,vmAttributes) :
        cmd_line = 'virsh create ' +vmConfFile
        g_virsh_command_lock.acquire()
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        g_virsh_command_lock.release()
        logger.info('p_startVM:%s' % cmd_output)
        if cmd_status == 0:
            ret = 0      
    else:
        logger.error('p_startVM: write file is error ' )
    return ret

def p_has_cdrom():
    ret = False
    try:
        if os.path.exists('/dev/sr0'):
            ret = True
    except:
        ret = False
    return ret

# generate domain xml templet
def p_generate_domain_xml(vmconfigXml):
    logger.info('this is a p_generate_domain_xml first')
    xml = ''
    doc = Document()
    domain = doc.createElement('domain')
    domain.setAttribute('type', 'kvm')
    doc.appendChild(domain)
    name = doc.createElement('name')
    img_name = doc.createTextNode(vmconfigXml['name'])
    name.appendChild(img_name)
    domain.appendChild(name)

    os = doc.createElement('os')
    type = doc.createElement('type')
    type.setAttribute('arch', 'x86_64')
    type.setAttribute('machine', 'pc')
    hvm = doc.createTextNode('hvm')
    type.appendChild(hvm)
    os.appendChild(type)
    boot1 = doc.createElement('boot')
    boot1.setAttribute('dev','hd')
    os.appendChild(boot1)
    boot2 = doc.createElement('boot')
    boot2.setAttribute('dev', 'cdrom')
    os.appendChild(boot2)    
    
    domain.appendChild(os)

    #opaque_content = ' -rtc base=localtime,driftfix=slew -soundhw ac97 -vga qxl -device virtio-serial -chardev spicevmc,id=vdagent,name=vdagent -device virtserialport,chardev=vdagent,name=com.redhat.spice.0 -readconfig /etc/qemu/ich9-ehci-uhci.cfg -chardev spicevmc,name=usbredir,id=usbredirchardev1 -device usb-redir,chardev=usbredirchardev1,id=usbredirdev1,debug=3 -chardev spicevmc,name=usbredir,id=usbredirchardev2 -device usb-redir,chardev=usbredirchardev2,id=usbredirdev2,debug=3 -chardev spicevmc,name=usbredir,id=usbredirchardev3 -device usb-redir,chardev=usbredirchardev3,id=usbredirdev3,debug=3 -spice port=5900,password=password1!,disable-ticketing'
    logger.info('opaque:%s'%vmconfigXml['opaque'])
    opaque_content = vmconfigXml['opaque']
    logger.info('opaque:%s'%opaque_content)
    #opaque_content = '-rtc base=localtime,driftfix=slew -soundhw ac97 -vga qxl -spice port=SPICEPORT,password=PASSWORD  -device spicevmc'
    opaque = doc.createElement('opaque')
    content = doc.createTextNode(opaque_content)
    opaque.appendChild(content)
    domain.appendChild(opaque)

    features = doc.createElement('features')
    acpi = doc.createElement('acpi')
    features.appendChild(acpi)
    domain.appendChild(features)
    memory = doc.createElement('memory')

    memory_content = doc.createTextNode(vmconfigXml['vmMemmory'])
    logger.info('vmMemory:%s'%vmconfigXml['vmMemmory'])
    memory.appendChild(memory_content)
    domain.appendChild(memory)

    vcpu = doc.createElement('vcpu')
    vcpu_content = doc.createTextNode(vmconfigXml['vmCpuNum'])
    logger.info('vmMemory:%s'%vmconfigXml['vmCpuNum'])
    vcpu.appendChild(vcpu_content)
    domain.appendChild(vcpu)

    clock = doc.createElement('clock')
    clock.setAttribute('offset', 'localtime')
    domain.appendChild(clock)

    on_poweroff = doc.createElement('on_poweroff')
    on_poweroff_content = doc.createTextNode('destroy')
    on_poweroff.appendChild(on_poweroff_content)
    domain.appendChild(on_poweroff)

    on_reboot = doc.createElement('on_reboot')
    on_reboot_content = doc.createTextNode('restart')
    on_reboot.appendChild(on_reboot_content)
    domain.appendChild(on_reboot)

    on_crash = doc.createElement('on_crash')
    on_crash_content = doc.createTextNode('destroy')
    on_crash.appendChild(on_crash_content)
    domain.appendChild(on_crash)

    devices = doc.createElement('devices')
    emulator = doc.createElement('emulator')
    emulator_content = doc.createTextNode('/usr/bin/kvm')
    emulator.appendChild(emulator_content)
    devices.appendChild(emulator)
    disk = doc.createElement('disk')
    disk.setAttribute('type', 'file')
    disk.setAttribute('device', 'disk')
    driver = doc.createElement('driver')
    driver.setAttribute('name', 'qemu')
    disk.appendChild(driver)
    source = doc.createElement('source')
    source.setAttribute('file', vmconfigXml['targetDisk'])
    logger.info('targetdisk:%s'%vmconfigXml['targetDisk'])
    disk.appendChild(source)
    target = doc.createElement('target')
    target.setAttribute('dev', 'hda')
    target.setAttribute('bus', 'ide')
    disk.appendChild(target)
    devices.appendChild(disk)
    disk2 = doc.createElement('disk')
    #disk2.setAttribute('type','block')
    disk2.setAttribute('device', 'cdrom')
    if vmconfigXml['diskType'] != None:
        disk2.setAttribute('type', vmconfigXml['diskType'])
        logger.info('disk2:%s'% vmconfigXml['diskType'])
    source = doc.createElement('source')
    if vmconfigXml['isoPath'] != None and vmconfigXml['diskName'] != None:
        source.setAttribute(vmconfigXml['diskName'], vmconfigXml['isoPath'])
        logger.info('source: %s' % vmconfigXml['isoPath'])

    disk2.appendChild(source)
    target = doc.createElement('target')
    target.setAttribute('dev', 'hdc')
    target.setAttribute('bus', 'ide')
    disk2.appendChild(target)
    devices.appendChild(disk2)

    #extern disk
    if  vmconfigXml['extDisk'] and vmconfigXml['extDiskFile']!=None:
        disk3 = doc.createElement('disk')
        disk3.setAttribute('device', 'disk')
        disk3.setAttribute('type', 'file')
        source = doc.createElement('source')
        source.setAttribute('file', vmconfigXml['extDiskFile'])
        disk3.appendChild(source)
        target = doc.createElement('target')
        target.setAttribute('dev', 'hdb')
        target.setAttribute('bus', 'ide')
        disk3.appendChild(target)
        devices.appendChild(disk3)
    
    interface = doc.createElement('interface')
    source = doc.createElement('source')

    if(vmconfigXml['netMode'] == 'BRIDGE'):     
        interface.setAttribute('type', 'bridge')
        source.setAttribute('bridge', 'br0')
        if vmconfigXml['publicMac'] != None:
            mac = doc.createElement('mac')
            mac.setAttribute('address', vmconfigXml['publicMac'])
            logger.info('publicMac: %s '% vmconfigXml['publicMac'])
            interface.appendChild(mac)                       

    else:
        interface.setAttribute('type', 'user')
        source.setAttribute('network', 'default')
    interface.appendChild(source)
    
    model = doc.createElement('model')
    model.setAttribute('type', 'rtl8139')
    interface.appendChild(model)
    devices.appendChild(interface)
    input = doc.createElement('input')
    input.setAttribute('type', 'tablet')
    input.setAttribute('bus', 'usb')
    devices.appendChild(input)
    domain.appendChild(devices)
    xml = doc.toxml()
    logger.info(xml)

    return xml


#p_runInstanceThread_job
def p_runInstanceThread_job(transactionID, imageID, user):
    "p_runInstanceThread_job"
    switch.acquire()
    transaction = p_getTransactionStatus(transactionID)
    insId = transaction['instanceID']
    user = transaction['user']
    insPort = p_get_available_port(user,imageID)
    transaction['instancePort'] = insPort
    passwords = str(transaction['instancePassword'])
    switch.release()
    instancePath = p_getImageMakingInstancePath(user, insId)
    logger.info('instancePath %s' % (instancePath))
    if not os.path.exists(instancePath):
        try:
            os.makedirs(instancePath)
        except:
            log_file = 'Create ' + instancePath + ' error!'
            logger.error(log_file)
            p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
            return -1
    targetdisk = p_getInstanceFile(user, insId)
    sourcedisk = p_getCacheFile(imageID)
    if(transaction['createMode'] == 'IMG' or transaction['createMode'] == 'P2V'):
        if not os.path.exists(targetdisk):
            res = p_prepareCopyOnWriteImage(sourcedisk, targetdisk)
            if res < 0:
                p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
                return -1

    #generate default domain xml 
    logger.info('before call p_creatImage_domain_xml')
    vmconfigXml = {}
    
    vmconfigXml['vmMemmory'] = str(VM_MEMERY)
    vmconfigXml['vmCpuNum'] = str(VM_CPUS)
    vmconfigXml['targetDisk'] = targetdisk
    vmconfigXml['name'] = insId
    vmconfigXml['publicMac'] = None
    port = str(insPort)
    if(transaction['createMode'] == 'ISO' and transaction['platform']=='ubuntu'):
        vmconfigXml['opaque'] = '-rtc base=localtime,driftfix=slew -soundhw ac97 -vga cirrus -spice port='+port+',password='+passwords+',disable-ticketing -device virtio-serial -chardev spicevmc,id=vdagent,name=vdagent ' + p_get_usbredir_opaque()
    else:
        vmconfigXml['opaque'] = '-rtc base=localtime,driftfix=slew -soundhw ac97 -vga qxl -spice port='+port+',password='+passwords+',disable-ticketing -device virtio-serial -chardev spicevmc,id=vdagent,name=vdagent ' + p_get_usbredir_opaque()  
    vmconfigXml['netMode'] = 'NAT'
    
    if(transactionID != None):
        transaction = p_getTransactionStatus(transactionID)
        if(transaction['createMode'] == 'ISO' and transaction['bootFrom'] == 'cdrom'):
            vmconfigXml['bootDisk'] = 'cdrom'             # boot from cdrom
        else:
            vmconfigXml['bootDisk'] = 'hd'
    else:
        vmconfigXml['bootDisk'] = 'hd'
    
    
    if(transactionID != None):
        transaction = p_getTransactionStatus(transactionID)
        if(transaction['createMode'] == 'ISO'):
            vmconfigXml['diskName'] = 'file'
            vmconfigXml['isoPath'] = ISO_FILE_PATH + transaction['imageID'] + '.' + ISO_EXTERN_NAME   # add the iso to cdrom
            vmconfigXml['diskType'] = 'file'
        else:
            if p_has_cdrom() :
                vmconfigXml['diskName'] = 'dev'
                vmconfigXml['isoPath'] = '/dev/sr0'
                vmconfigXml['diskType'] = 'block'
            else:
                vmconfigXml['diskName'] = None
                vmconfigXml['isoPath'] = None
                vmconfigXml['diskType'] = None                
    else:
        if p_has_cdrom() :
            vmconfigXml['diskName'] = 'dev'
            vmconfigXml['isoPath'] = '/dev/sr0'
            vmconfigXml['diskType'] = 'block'
        else:
            vmconfigXml['diskName'] = None
            vmconfigXml['isoPath'] = None
            vmconfigXml['diskType'] = None            
    vmconfigXml['extDisk'] = False
    vmconfigXml['extDiskFile']=None
    xml = p_generate_domain_xml(vmconfigXml)
    #xml = p_creatImage_domain_xml('NAT',transactionID,targetdisk,insId,user,imageID,insPort,passwords)
    logger.info(' after call p_creatImage_domain_xml')    

    ret = p_startVM(insId,xml)

    if ret == 0:
        p_updateTransactionState(thd_TRANSACT_STATE.PENDING, transactionID)
    else:
        p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)

    return ret

def p_euca_create_preference_file(clientdata, preferenceFile):
    ret = False
    if(clientdata != None):
        netinfo = clientData.net_info
        if (netinfo != None):
            fh = open(preferenceFile, 'a')
            
            publicip ='0.0.0.0' 
            if(netinfo.public_ip != None):
                publicip=netinfo.public_ip
            
            netmask = '0.0.0.0'
            if(netinfo.netmask != None):
                netmask = netinfo.netmask
            
            gateway = '0.0.0.0'
            if(netinfo.gateway != None):
                gateway = netinfo.gateway
            
            fileStr = publicip + ' ' + netmask + ' ' + gateway
            fh.write(fileStr)
            fh.write('\r\n')
            fh.close()
            ret = True
    return ret

def _is_local_node():
    ret = False
    host_ip = utility.get_local_publicip()
    ldap_ip = utility.get_ldap_server()
    if host_ip!=None and ldap_ip!=None:
        node_info = OpenLdap.p_get_nodeinfo_by_ip(ldap_ip,host_ip)
        if node_info!=None:
            ret = node_info.isLocal
    return ret
    
'''准备运行的instance副本,并返回instance副本文件路径
   super用戶运行时,准备好微调的instance副本(/var/lib/eucalyptus/.luhya/cache/emi-xxxxxx/adjustion/machine),并返回
   普通用戶运行时,准备临时的instance副本(/var/lib/eucalyptus/./luhya/instance/user/emi-xxxxxx/machine),并返回'''
def p_prepare_running_instance(transaction):
    targetdisk = None
    clientData = transaction['clientData']
    insId = transaction['instanceID']
    if clientData == None :
        return None	
    
    user = clientData.user
    imageID = clientData.image_id
    adjustionPath = p_getImageMakingCachePath(imageID) + 'adjustion'+ '/'
    instancePath = p_getImageMakingInstancePath(user, insId)
    
    sourcedisk = p_getCacheFile(imageID)    #/var/lib/eucalyptus/./luhya/cache/emi-xxxxxx/machine
    adjustiondisk = adjustionPath + DEFAULT_IMAGE_NAME #/var/lib/eucalyptus/./luhya/cache/emi-xxxxxx/adjustion/machine
    instancedisk = instancePath + DEFAULT_IMAGE_NAME  #/var/lib/eucalyptus/./luhya/instance/user/emi-xxxxxx/machine
    
    #check tmp instance folder, if not exist, create it    
    if not os.path.exists(instancePath):
        try:
            logger.info('check instance path %s' % (instancePath))
            os.makedirs(instancePath)
        except:
            log_file = 'Create ' + instancePath + ' failed!'
            logger.error(log_file)
            return None
    logger.info("clientData in tran: %s" %str(clientData))
    #check adjustion folder, if not exist, create it    
    if not os.path.exists(adjustionPath):
        try:
            logger.info('check adjust path %s' % (adjustionPath))
            os.makedirs(adjustionPath)
        except:
            log_file = 'Create ' + adjustionPath + ' failed!'
            logger.error(log_file)
            return None

    #prepare running instance
    if clientData.run_as_super == True :
        #check adjustion instance,if not exist, create it
        logger.info('check adjust run as super')   
        if not os.path.exists(adjustiondisk):
            res = p_prepareCopyOnWriteImage(sourcedisk, adjustiondisk)
            if res < 0:
                logger.error('create adjust image  failed')
                return None
        
        #run instance from adjustion disk       
        targetdisk = adjustiondisk  
        
    else: # run_as_super == false
        logger.info('real user  run ')
        isNewInstance = False
        #check if clear instancedisk
        if(clientData.vm_info.is_clear_power_off == True):
            if os.path.exists(instancedisk):
                os.remove(instancedisk)
            logger.info('remove tmp instance disk %s' % (instancedisk))  
            isNewInstance = True  
            
        else: #is_clear_power_off == False
            if(not os.path.exists(instancedisk)):
                isNewInstance = True
            else:
                isNewInstance = False
           
           
        #create instancedisk
        if isNewInstance == True :
            tmp_sourcedisk = sourcedisk
            if(os.path.exists(adjustiondisk)):
                tmp_sourcedisk = adjustiondisk
            else:
                tmp_sourcedisk = sourcedisk
            res = p_prepareCopyOnWriteImage(tmp_sourcedisk, instancedisk)
            if res < 0:
                logger.error('create instance image  failed')
                return None

        #run instance from tmp instance disk
        targetdisk = instancedisk  
    logger.info('the run fuben: %s' %targetdisk)
    return targetdisk
	
def p_euca_real_run_instance_thread_job(transactionID):
    switch.acquire()
    transaction = p_euca_get_transaction(transactionID)
    insId = transaction['instanceID']    
    insPort = transaction['instancePort']
    passwords = str(transaction['instancePassword'])
    clientData = transaction['clientData']
    switch.release()

    #check client data    
    if clientData == None :
        logger.error('Can not find Client Data to run instance : ' + insId)
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return RET_ERROR	

    #check and prepare copy on write instance
    '''user = clientData.user
    imageID = clientData.image_id
    instancePath = p_getImageMakingInstancePath(user, insId)    
    logger.info('check instance path %s' % (instancePath))
    if not os.path.exists(instancePath):
        try:
            os.makedirs(instancePath)
        except:
            log_file = 'Create ' + instancePath + ' failed!'
            logger.error(log_file)
            p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
            return RET_ERROR

    targetdisk = instancePath + DEFAULT_IMAGE_NAME
    if not os.path.exists(targetdisk):
        sourcedisk = p_getCacheFile(imageID)
        res = p_prepareCopyOnWriteImage(sourcedisk, targetdisk)
        if res < 0:
            p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
            logger.error('create copy on write image failed')
            return RET_ERROR'''
    #prepare running instance 
    targetdisk = p_prepare_running_instance(transaction)
    if targetdisk == None :
        log_file = 'Create instance for' + insId + ' failed!'
        logger.error(log_file)
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return RET_ERROR
    
    #write network info into instance when running in bridge mode
    #if(clientData.net_info.net_mode == 'BRIDGE' and clientData.net_info.ip_dhcp == False):		
    #    preferenceFile = instancePath + 'preference.txt'
    #    if(os.path.exists(preferenceFile)):
    #        os.remove(preferenceFile)
    #    if(p_euca_create_preference_file(clientData, preferenceFile)):
    #        cmd_line = 'sudo injector.pl -i ' + targetdisk + ' ' + preferenceFile
    #        logger.info(cmd_line)
    #        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)

    #prepare instance running properties...
    vmconfigXml = {}

    #set vm name
    vmconfigXml['name'] = insId

    #set cpu cores and memory    
    cpus = str(VM_CPUS)
    mem = str(VM_MEMERY)
    if clientData.vm_info != None :
        if clientData.vm_info.vm_cpu != None and clientData.vm_info.vm_cpu > 0:
            cpus = str(clientData.vm_info.vm_cpu)
        if clientData.vm_info.vm_memory != None and clientData.vm_info.vm_memory > 0:
            mem = str(clientData.vm_info.vm_memory*1024) #MB -> KB 
    if(_is_local_node()):
        hdSource = utility.utility_get_current_resource()
        can_use_cpu = 1
        if hdSource.cpu_num >1:
            can_use_cpu = hdSource.cpu_num -1
        if can_use_cpu<int(cpus):
            cpus = str(can_use_cpu)                        # the remain cpus to run instance
        if hdSource.free_memory-VM_MEMERY < int(mem):
            mem = str(hdSource.free_memory-VM_MEMERY)           # the remain memory to run instance kB
        logger.debug('local node , run instance use cpu:%s memory: %s' %(cpus,mem))

    logger.debug('local node , real cpu:%s memory: %s' %(cpus,mem))
    vmconfigXml['vmMemmory'] = mem
    vmconfigXml['vmCpuNum'] = cpus

    #set target disk
    vmconfigXml['bootDisk'] = 'hd'
    vmconfigXml['targetDisk'] = targetdisk

    #set opaque properties
    port = str(insPort)
    ldap_ip = utility.get_ldap_server()
    platform = OpenLdap.get_image_platform(ldap_ip, clientData.image_id)
    if platform == 'ubuntu':
        vmconfigXml['opaque'] = '-rtc base=localtime,driftfix=slew -soundhw ac97 -vga cirrus -spice port='+port+',password='+passwords+',disable-ticketing -device virtio-serial -chardev spicevmc,id=vdagent,name=vdagent '+p_get_usbredir_opaque()
    else:
        vmconfigXml['opaque'] = '-rtc base=localtime,driftfix=slew -soundhw ac97 -vga qxl -spice port='+port+',password='+passwords+',disable-ticketing -device virtio-serial -chardev spicevmc,id=vdagent,name=vdagent ' + p_get_usbredir_opaque()
                                
    dumpFile = p_get_restore_dump_file(targetdisk)
    if(g_auto_migrate_state_lists.has_key(clientData.user+clientData.image_id)) and dumpFile != None:
        g_auto_migrate_state_switch.acquire()
        bAttach = g_auto_migrate_state_lists[clientData.user+clientData.image_id]
        g_auto_migrate_state_lists[clientData.user+clientData.image_id] = False
        g_auto_migrate_state_switch.release()
        if(bAttach):
            if os.path.isfile(dumpFile):
                vmconfigXml['opaque'] = vmconfigXml['opaque'] + ' ' +'-incoming \'exec:cat '+dumpFile+'\''
                logger.info('live restore opaque:%s'%vmconfigXml['opaque'])  
    
    #set cdrom
    if p_has_cdrom():
        vmconfigXml['diskName'] = 'dev'
        vmconfigXml['diskType'] = 'block'
        vmconfigXml['isoPath'] = '/dev/sr0'
    else:
        vmconfigXml['diskName'] = None
        vmconfigXml['isoPath'] = None
        vmconfigXml['diskType'] = None        

    #vmconfigXml['netMode'] = 'NAT'		    
    #set network
    if clientData.net_info != None:
	    #set net mode
        if clientData.net_info.net_mode != None:
            vmconfigXml['netMode'] = clientData.net_info.net_mode
        else:#defaultly, use NAT mode
            vmconfigXml['netMode'] = 'NAT'		    

        #set mac address
        if clientData.net_info.public_mac != None:
            mac = clientData.net_info.public_mac.split('-')
            if len(mac) == 6:
                vmconfigXml['publicMac'] = mac[0]+':'+mac[1]+':'+mac[2]+':'+mac[3]+':'+mac[4]+':'+mac[5]
            else:
                vmconfigXml['publicMac'] = None
        else:
            vmconfigXml['publicMac'] = None
    else:#clientData.net_info = None
        vmconfigXml['netMode'] = 'NAT'
	
    logger.info('p_euca_real_run_instance_thread_job get extdisk ')
    vmconfigXml['extDisk']=False
    vmconfigXml['extDiskFile']=None
    if clientData.peripheral!=None:
        vmconfigXml['extDisk'] = clientData.peripheral.is_external_device
        if clientData.peripheral.is_external_device!=None and clientData.peripheral.is_external_device:
            ext_disk_path  = p_getImageMakingInstancePath(clientData.user, insId) 
            if _is_local_node():
                ext_disk_path = EXT_DISK_NODE
                if os.path.exists(ext_disk_path+ EXT_DISK_FILE):
                    vmconfigXml['extDiskFile'] = ext_disk_path+EXT_DISK_FILE
                else:
                    vmconfigXml['extDiskFile']=None
#            else:            # remote node mode
#                if os.path.exists(ext_disk_path+ EXT_DISK_FILE):
#                    vmconfigXml['extDiskFile'] = instancePath+EXT_DISK_FILE
#                else:
#                    if os.path.exists(EXT_DISK_NODE+ EXT_DISK_FILE):
#                        cmd = 'cp '+ EXT_DISK_NODE+EXT_DISK_FILE + ' ' +ext_disk_path+ EXT_DISK_FILE
#                        cmd_status, cmd_output = commands.getstatusoutput(cmd)
#                        if cmd_status:
#                            vmconfigXml['extDiskFile'] = None
#                        else:
#                            vmconfigXml['extDiskFile'] = ext_disk_path+EXT_DISK_FILE
#                    else:
#                        vmconfigXml['extDiskFile'] = None

    logger.info('p_euca_real_run_instance_thread_job vmconfigXml: %s ' % str(vmconfigXml))
    xml = p_generate_domain_xml(vmconfigXml)
    logger.info('p_euca_real_run_instance_thread_job xml: %s ' % xml)
    ret = p_startVM(insId,xml)  
    
    if ret == 0:
        p_euca_update_transaction_state(thd_TRANSACT_STATE.PENDING, transactionID)
    else:
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)

    return ret

# p_runInstanceThread
class p_runInstanceThread(threading.Thread):
    def __init__(self, transactionID, cloudapi_user, imageID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID
        self.cloudapi_user = cloudapi_user
        self.imageID = imageID

    def run(self):
        ret = p_runInstanceThread_job(self.transactionID, self.imageID, self.cloudapi_user)
        if(ret):
            pass
            #cloudapi_log()

class p_euca_real_run_instance_thread(threading.Thread):
    def __init__(self, transactionID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID

    def run(self):
        ret = p_euca_real_run_instance_thread_job(self.transactionID)
        if(ret):
            pass

def p_getSubmitStatus(transaction):
    return

def p_getInstanceState(instanceID):
    logger.info('p_getInstanceState: %s' % instanceID)
    status = None
    cmd_line = "virsh list |grep " + instanceID
    g_virsh_command_lock.acquire()
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    g_virsh_command_lock.release()
    if(cmd_status == 0):
        if cmd_output!=None:
            strSplit = cmd_output.split(' ')
            if len(strSplit)>0:
                status = strSplit[len(strSplit) - 1]
    logger.info('p_getInstanceState: %s' % status)
    return status


def p_getAllTransaction():
    logger.info('p_getAllTransaction...')
    info_list = []
    switch.acquire()
    for tid in transactions.keys():
        if(tid != 'error'):
            transaction = transactions[tid]
            newTran = None
            newImage = None
            if transaction['state'] == thd_TRANSACT_STATE.PENDING:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if(insStatus != None):
                    if(insStatus == 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.RUNNING
                    else:
                        transaction['state'] = thd_TRANSACT_STATE.PENDING
            if transaction['state'] == thd_TRANSACT_STATE.RUNNING or transaction[
                                                                    'state'] == thd_TRANSACT_STATE.RUN_FAILED:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                else:
                    if(insStatus != 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED
            if transaction['state'] == thd_TRANSACT_STATE.SHUTTING_DOWN:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                else:
                    if(insStatus != 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED
            if transaction['state'] == thd_TRANSACT_STATE.SUBMITTING:
                p_getSubmitStatus(transaction)

            if(transaction['newImageInfo'] != None):
                newImage = thd_ImageInfo(\
                    imageId=transaction['newImageInfo']['imageId'],\
                    name=transaction['newImageInfo']['name'],\
                    imageCategory=transaction['newImageInfo']['imageCategory'],\
                    description=transaction['newImageInfo']['description'],\
                    platform=transaction['newImageInfo']['platform'],\
                    size=transaction['newImageInfo']['size'],\
                    imageType=transaction['newImageInfo']['imageType'],\
                    createTime=transaction['newImageInfo']['createTime'])
            newTran = thd_Transaction(\
                transactionID=transaction['transactionID'],\
                imageID=transaction['imageID'], state=transaction['state'],\
                instanceID=transaction['instanceID'],\
                instancePort=transaction['instancePort'],\
                instancePassword=transaction['instancePassword'],\
                downloadProgress=transaction['downloadProgress'],\
                modifyTime=transaction['modifyTime'],\
                submitTime=transaction['submitTime'],\
                submitState=transaction['submitState'],\
                submitProgress=transaction['submitProgress'],\
                imageSize=transaction['imageSize'],\
                uploadProgress=transaction['uploadProgress'],\
                uploadSpeed=transaction['uploadSpeed'],\
                user=transaction['user'],\
                sumbitEstimatedTime=transaction['sumbitEstimatedTime'],\
                createMode=transaction['createMode'],\
                platform=transaction['platform'],\
                vmcpu=transaction['vmcpu'],\
                vmmemory=transaction['vmmemory'],\
                vmdisk=transaction['vmdisk'],\
                newImageInfo=newImage)
            logger.info('newTran:%s' % (newTran))
            info_list.append(newTran)
    switch.release()
    return info_list


def p_euca_get_run_instance_transactions(userName):
    logger.info('p_euca_get_run_instance_transactions... %s', userName)
    info_list = []
    switch.acquire()
    for tid in euca_transactions.keys():
        if tid != 'error' :
            if userName =='admin' or OpenLdap.p_is_admin(utility.get_ldap_server(),userName) or euca_transactions[tid]['user'] == userName:
                transaction = euca_transactions[tid]
                newTran = None
                newImage = None
                if transaction['state'] == thd_TRANSACT_STATE.INIT:
                    insStatus = p_getInstanceState(transaction['instanceID'])
                    if (insStatus != None):
                        if(insStatus == 'running'):
                            transaction['state'] = thd_TRANSACT_STATE.RUNNING
                if transaction['state'] == thd_TRANSACT_STATE.PENDING or transaction['state']==thd_TRANSACT_STATE.TERMINATED:
                    insStatus = p_getInstanceState(transaction['instanceID'])
                    if(insStatus != None):
                        if(insStatus == 'running'):
                            transaction['state'] = thd_TRANSACT_STATE.RUNNING
                if transaction['state'] == thd_TRANSACT_STATE.RUNNING or transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED:
                    insStatus = p_getInstanceState(transaction['instanceID'])
                    if (insStatus == None):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                    else:
                        if(insStatus != 'running' and insStatus!='error'):
                            transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                if transaction['state'] == thd_TRANSACT_STATE.SHUTTING_DOWN:
                    insStatus = p_getInstanceState(transaction['instanceID'])
                    if (insStatus == None):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED

                newTran = thd_eucaTransaction(\
                        transactionID=transaction['transactionID'],\
                        imageID=transaction['imageID'], state=transaction['state'],\
                        instanceID=transaction['instanceID'],\
                        instancePort=transaction['instancePort'],\
                        instancePassword=transaction['instancePassword'],\
                        downloadProgress=transaction['downloadProgress'],\
                        imageSize=transaction['imageSize'],\
                        nodeIp=transaction['nodeIp'],\
                        user=transaction['user'],\
                        modifyTime=transaction['modifyTime'])
                info_list.append(newTran)
    switch.release()
    return info_list

def p_get_transId_by_user_image(user,imageId):
    transId = None
    switch.acquire()
    for tid in euca_transactions.keys():    
        transaction = euca_transactions[tid]
        if transaction!=None and transaction['user']==user and transaction['imageID']==imageId :
            transId = transaction['transactionID']
    logger.info('p_get_transId_by_user_image: %s' % transId)
    switch.release()
    return transId

def p_getTransactionStatusById(transactionID):
    logger.info('p_getTransactionStatusById %s' % (transactionID))
    info = None
    newImage = None
    switch.acquire()
    if transactions.has_key(transactionID):
        transaction = transactions[transactionID]
        if transaction['transactionID'] == transactionID:
            if transaction['state'] == thd_TRANSACT_STATE.PENDING:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus != None):
                    if(insStatus == 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.RUNNING
                    else:
                        transaction['state'] = thd_TRANSACT_STATE.PENDING
            if transaction['state'] == thd_TRANSACT_STATE.RUNNING or transaction[
                                                                    'state'] == thd_TRANSACT_STATE.RUN_FAILED:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                else:
                    if(insStatus != 'running' and insStatus!='error'):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED
            if transaction['state'] == thd_TRANSACT_STATE.SHUTTING_DOWN:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                else:
                    if(insStatus != 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED

            if transaction['state'] == thd_TRANSACT_STATE.SUBMITTING:
                p_getSubmitStatus(transaction)
            if(transaction['newImageInfo'] != None):
                newImage = thd_ImageInfo(\
                    imageId=transaction['newImageInfo']['imageId'],\
                    name=transaction['newImageInfo']['name'],\
                    imageCategory=transaction['newImageInfo']['imageCategory'],\
                    description=transaction['newImageInfo']['description'],\
                    platform=transaction['newImageInfo']['platform'],\
                    size=transaction['newImageInfo']['size'],\
                    imageType=transaction['newImageInfo']['imageType'],\
                    createTime=transaction['newImageInfo']['createTime'])
            info = thd_Transaction(\
                transactionID=transaction['transactionID'],\
                imageID=transaction['imageID'],\
                state=transaction['state'],\
                instanceID=transaction['instanceID'],\
                instancePort=transaction['instancePort'],\
                instancePassword=transaction['instancePassword'],\
                downloadProgress=transaction['downloadProgress'],\
                modifyTime=transaction['modifyTime'],\
                submitTime=transaction['submitTime'],\
                submitState=transaction['submitState'],\
                submitProgress=transaction['submitProgress'],\
                imageSize=transaction['imageSize'],\
                uploadProgress=transaction['uploadProgress'],\
                uploadSpeed=transaction['uploadSpeed'],\
                user=transaction['user'],\
                sumbitEstimatedTime=transaction['sumbitEstimatedTime'],\
                createMode=transaction['createMode'],\
                platform=transaction['platform'],\
                vmcpu=transaction['vmcpu'],\
                vmmemory=transaction['vmmemory'],\
                vmdisk=transaction['vmdisk'],\
                newImageInfo=newImage)
    logger.info('info: %s' % str(info))
    switch.release()
    return info


def p_get_run_instance_transaction_byid(transactionID):
    logger.info('p_get_run_instance_transaction_byid %s' % (transactionID))
    info = thd_eucaTransaction()
    switch.acquire()
    if euca_transactions.has_key(transactionID):
        transaction = euca_transactions[transactionID]
        if transaction['transactionID'] == transactionID:
            if transaction['state'] == thd_TRANSACT_STATE.INIT:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus != None):
                    if(insStatus == 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.RUNNING
            if transaction['state'] == thd_TRANSACT_STATE.PENDING:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus != None):
                    if(insStatus == 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.RUNNING
                    else:
                        transaction['state'] = thd_TRANSACT_STATE.PENDING
            if transaction['state'] == thd_TRANSACT_STATE.RUNNING or transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED
                else:
                    if(insStatus != 'running'):
                        transaction['state'] = thd_TRANSACT_STATE.TERMINATED
            if transaction['state'] == thd_TRANSACT_STATE.SHUTTING_DOWN:
                insStatus = p_getInstanceState(transaction['instanceID'])
                if (insStatus == None):
                    transaction['state'] = thd_TRANSACT_STATE.TERMINATED

            info = thd_eucaTransaction(\
                    transactionID=transaction['transactionID'],\
                    imageID=transaction['imageID'],\
                    state=transaction['state'],\
                    instanceID=transaction['instanceID'],\
                    instancePort=transaction['instancePort'],\
                    instancePassword=transaction['instancePassword'],\
                    downloadProgress=transaction['downloadProgress'],\
                    imageSize=transaction['imageSize'],\
                    nodeIp=transaction['nodeIp'],\
                    user=transaction['user'],\
                    modifyTime=transaction['modifyTime'])
    logger.debug('transaction info: %s' % str(euca_transactions))
    switch.release()
    return info

    
# p_terminateInstance
def p_terminateInstance(instanceID):
    "p_terminateInstance"
    cmd_line = 'virsh destroy INSTANCE'
    cmd_line = cmd_line.replace('INSTANCE', instanceID)
    g_virsh_command_lock.acquire()
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    g_virsh_command_lock.release()
    # log cmd_output
    logger.info('cmd_status: %s' % str(cmd_status))
    if cmd_status:
        pass
        # log_error
        return -1
    return 0

# p_reboot Instance
def p_rebootInstance(instanceID):
    "p_terminateInstance"
    cmd_line = 'virsh reboot INSTANCE'
    cmd_line = cmd_line.replace('INSTANCE', instanceID)
    g_virsh_command_lock.acquire()
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    g_virsh_command_lock.release()
    # log cmd_output
    logger.info('cmd_status: %s' % str(cmd_status))
    if cmd_status:
        pass
        # log_error
        return -1
    return 0



def p_stopInstancebyBaseImage(transactionID):
    logger.info('p_stopInstancebyBaseImage %s' % (transactionID))
    transaction = p_getTransactionStatus(
        transactionID)                                       # get transaction according transactionID
    if transaction == None:                                                                   # instance id not exist
        logger.error('can not find transaction %s' % str(transactionID))
        return -1
    p_updateModifyTime(transactionID)
    instanceID = transaction['instanceID']
    p_updateTransactionState(thd_TRANSACT_STATE.SHUTTING_DOWN, transactionID)
    return p_terminateInstance(instanceID)


def p_euca_stop_instance(transactionID):
    logger.info('p_euca_stop_instance %s' % (transactionID))
    transaction = p_euca_get_transaction(transactionID) # get transaction according transactionID
    if transaction == None:                                                                   # instance id not exist
        logger.error('can not find transaction %s' % str(transactionID))
        return -1
    instanceID = transaction['instanceID']
    p_euca_update_transaction_state(thd_TRANSACT_STATE.SHUTTING_DOWN, transactionID)
    return p_terminateInstance(instanceID)

# p_deleteMakeImageTransaction
def p_deleteMakeImageTransaction(transactionID):
    logger.info('p_deleteMakeImageTransaction %s' % (transactionID))

    transaction = p_getTransactionStatus(
        transactionID)                                       # get transaction according transactionID
    if transaction == None:                                                                   # instance id not exist
        logger.error('can not find transaction %s' % str(transactionID))
        return False
    instanceID = transaction['instanceID']
    user = transaction['user']

    #   terminate instance if it is running
    p_terminateInstance(instanceID)

    #   remove instance file
    instancePath = p_getImageMakingInstancePath(user, instanceID)
    try:
        logger.info('p_deleteMakeImageTransaction instance path: %s' % (instancePath))
        shutil.rmtree(instancePath, True)
    except os.error:
        logger.error('p_deleteMakeImageTransaction delete instance path: %s error' % (instancePath))
        #   delele transaction
    del transactions[transactionID]
    return True

# p_updateNewImageLen
def p_updateNewImageLen(newImageLen, transactionID):
    "p_updateNewImageLen"
    switch.acquire()
    if transactions.has_key(transactionID):
        if transactions[transactionID]['newImageInfo'] == None:
            newImageInfo = {}
            newImageInfo['imageId'] = None
            newImageInfo['imageLocation'] = None
            newImageInfo['imageState'] = None
            newImageInfo['imageOwnerId'] = None
            newImageInfo['architecture'] = None
            newImageInfo['imageType'] = None
            newImageInfo['kernelId'] = None
            newImageInfo['ramdiskId'] = None
            newImageInfo['isPublic'] = None
            newImageInfo['signature'] = None
            newImageInfo['name'] = None
            newImageInfo['imageCategory'] = None
            newImageInfo['description'] = None
            newImageInfo['platform'] = None
            newImageInfo['ownerName'] = None
            newImageInfo['vmStyle'] = None
            newImageInfo['Groups'] = None
            newImageInfo['OS'] = None
            newImageInfo['createTime'] = None
            newImageInfo['size'] = newImageLen
            newImageInfo['manifest'] = None
            transactions[transactionID]['newImageInfo'] = newImageInfo
        else:
            transactions[transactionID]['newImageInfo']['size'] = newImageLen
    else:
        transaction = {}
        newImageInfo = {}
        newImageInfo['imageId'] = None
        newImageInfo['imageLocation'] = None
        newImageInfo['imageState'] = None
        newImageInfo['imageOwnerId'] = None
        newImageInfo['architecture'] = None
        newImageInfo['imageType'] = None
        newImageInfo['kernelId'] = None
        newImageInfo['ramdiskId'] = None
        newImageInfo['isPublic'] = None
        newImageInfo['signature'] = None
        newImageInfo['name'] = None
        newImageInfo['imageCategory'] = None
        newImageInfo['description'] = None
        newImageInfo['platform'] = None
        newImageInfo['ownerName'] = None
        newImageInfo['vmStyle'] = None
        newImageInfo['Groups'] = None
        newImageInfo['OS'] = None
        newImageInfo['createTime'] = None
        newImageInfo['size'] = newImageLen
        newImageInfo['manifest'] = None
        transaction['newImageInfo'] = newImageInfo
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateUploadSpeed
def p_updateUploadSpeed(uploadSpeed, transactionID):
    "p_updateUploadSpeed"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['uploadSpeed'] = uploadSpeed
    else:
        transaction = {}
        transactions[transactionID]['uploadSpeed'] = uploadSpeed
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateUploadProgress
def p_updateUploadProgress(uploadProgress, transactionID):
    "p_updateUploadProgress"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['uploadProgress'] = uploadProgress
    else:
        transaction = {}
        transactions[transactionID]['uploadProgress'] = uploadProgress
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateCombineImageSize
def p_updateCombineImageSize(imageSize, transactionID):
    "p_updateCombineImageSize"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['newImageInfo']['size'] = imageSize
        logger.info('p_updateCombineImageSize %s' % (transactions[transactionID]['newImageInfo']['size'] ))
    else:
        transaction = {}
        transactions[transactionID]['newImageInfo']['size'] = imageSize
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateSubmitProgress
def p_updateSubmitProgress(submitProgress, transactionID):
    "p_updateSubmitProgress"
    logger.info('p_updateSubmitProgress %d' % (submitProgress))
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['submitProgress'] = submitProgress
    else:
        transaction = {}
        transactions[transactionID]['submitProgress'] = submitProgress
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateSubmitStartTime
def p_updateSubmitStartTime(submitTime, transactionID):
    logger.info('p_updateSubmitStartTime %s' % str(submitTime))
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['submitTime'] = submitTime
    else:
        transaction = {}
        transactions[transactionID]['submitTime'] = submitTime
        transactions[transactionID] = transaction
    switch.release()
    return 0

#p_updateSubmitEndTime
def p_updateSubmitEndTime(submitTime, transactionID):
    logger.info('p_updateSubmitEndTime %s' % str(submitTime))
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['newImageInfo']['createTime'] = submitTime
    switch.release()
    return 0

# p_updateSubmitState    
def p_updateSubmitState(submit_state, transactionID):
    "p_updateSubmitState"
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['submitState'] = submit_state
    else:
        transaction = {}
        transaction['submitState'] = submit_state
        transactions[transactionID] = transaction
    switch.release()
    return 0


def p_releaseTransactionPort(transactionID):
    switch.acquire()
    if transactions.has_key(transactionID):
        transactions[transactionID]['instancePort'] = -1
    switch.release()


# p_combineImage
def p_combineImage(instanceFile, combineFile):
    cmd_line = 'qemu-img convert -O qcow2 %s %s' % (instanceFile, combineFile)
    logger.info('combining image : %s' % (cmd_line))
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logger.info('p_combineImage %s' % str(cmd_output))
    if cmd_status:
        logger.error('p_combineImage error')
        pass

# combineImage_thread
class combineImage_thread(threading.Thread):
    "combineImage_thread"

    def __init__(self, instanceFile, combineFile):
        threading.Thread.__init__(self)
        self.instanceFile = instanceFile
        self.combineFile = combineFile

    def run(self):
        logger.info('combineImage_thread running ...')
        ret = p_combineImage(self.instanceFile, self.combineFile)
        if(ret):
            logger.error('p_combineImage error')
            pass

    def stop(self):
        super(self).__stop()

# p_cloudbot_upload_boudle_thread
class p_cloudbot_upload_boudle_thread(threading.Thread):
    "p_cloudbot_upload_boudle_thread"

    def __init__(self, transactionID, convertImg, imageSaveFile,isoPath):
        threading.Thread.__init__(self)
        self.convertImg = convertImg
        self.imageSaveFile = imageSaveFile
        self.transactionID = transactionID
        self.isoPath = isoPath

    def run(self):
        logger.info('p_cloudbot_upload_boudle_thread running ...')
        ldap_ip =  utility.get_ldap_server()               
        walrusIp,walrusPort = OpenLdap.get_walrus_info(ldap_ip)
        if walrusIp!=None:
            cmd_file = 'touch '+'NULL>'+self.isoPath+'progress.log'
            logger.info('isoPath:%s' %cmd_file)
            commands.getstatusoutput(cmd_file)     
            cmd_line = 'rsync '+'-a '+'--progress '+'--bwlimit=6144 ' + self.convertImg + ' ' + walrusIp + ':' + self.imageSaveFile +' >'+self.isoPath+'progress.log'
            logger.info('p_cloudbot_upload_boudle : %s' %cmd_line)
            cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
            # log cmd_output
            if cmd_status:
                logger.error('cloudbot upload boudle error')
                p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, self.transactionID)
                p_updateSubmitState(thd_SubmitState.FAILED, self.transactionID)
                return -1
            else:
                logger.info('p_cloudbot_upload_boudle success')
                return 0                
        else:
            logger.error('cloudbot upload boudle error')
            p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, self.transactionID)
            p_updateSubmitState(thd_SubmitState.FAILED, self.transactionID)
            return -1            
        

    def stop(self):
        super(self).__stop()

    # p_register_image
# return None: error string:image id, OK
def p_register_image(manifest, eucarc):
    "p_register_image"
    cmd_line = 'euca-register MANIFEST --config EUCARC'
    cmd_line = cmd_line.replace('MANIFEST', manifest)
    cmd_line = cmd_line.replace('EUCARC', eucarc)
    logger.info('p_register_image : ' + cmd_line)
    imageID = None
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    if cmd_status:
        logger.error('p_register_image error')
        return imageID

    strSplit = cmd_output.split('\t')
    imageID = strSplit[1]
    logger.info('p_register_image success, new image id = %s' % (imageID))
    return imageID

# p_updateImageToLdap  
def p_updateImageToLdap(transactionID, newImageID,newImageLen):
    "p_updateImageToLdap"
    if not transactions.has_key(transactionID):
        return -1
    if not transactions[transactionID].has_key('newImageInfo'):
        return -1
    switch.acquire()
    transactions[transactionID]['newImageInfo']['imageId'] = newImageID
    transactions[transactionID]['newImageInfo']['size'] = newImageLen
    switch.release()
    transaction = transactions[transactionID]
    imageInfo = thd_ImageInfo()
    imageInfo.imageId=newImageID
    imageInfo.name=transaction['newImageInfo']['name']
    imageInfo.imageCategory=transaction['newImageInfo']['imageCategory']
    imageInfo.isPublic = 1
    imageInfo.HYPERVISOR='kvm'
    imageInfo.imageState='available'
    imageInfo.description=transaction['newImageInfo']['description']
    imageInfo.imageLocation=IMAGE_DEFAULT_PATH
    imageInfo.platform=transaction['platform']
    imageInfo.size=newImageLen
    imageInfo.imageType=transaction['newImageInfo']['imageType']
    imageInfo.vmStyle=DEFAULT_IMAGE_STYLE
    imageInfo.imageCategory=transaction['newImageInfo']['imageCategory']
    imageInfo.createTime=transaction['newImageInfo']['createTime']
    imageInfo.imageOwnerId=transaction['user']
    if(OpenLdap.p_add_image_info( utility.get_ldap_server(), imageInfo)):
        return 0
    return -1

def p_create_imageId(imagePath):
    m = hashlib.md5()
    m.update(imagePath+str(int(time.time())))
    strimg = IMAGE_PREFIX+m.hexdigest().upper()[0:8]
    return strimg

# p_submitImageThread_job
def p_submitImageThread_job(transactionID):
    "p_submitImageThread_job"

    #get current transaction
    transaction = p_getTransactionStatus(transactionID)
    if transaction == None:
        logger.error('get current transaction error')
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1
        #update initialization state
    p_updateModifyTime(transactionID)

    p_updateTransactionState(thd_TRANSACT_STATE.SUBMITTING, transactionID)
    p_updateSubmitState(thd_SubmitState.PENDING, transactionID)
    p_updateSubmitProgress(0, transactionID)
    p_updateUploadProgress(0, transactionID)
    p_updateSubmitStartTime(str(int(time.time())), transactionID)

    #combine Image
    instanceID = transaction['instanceID']
    user = transaction['user']
    instancePath = p_getImageMakingInstancePath(user, instanceID)
    instanceFile = p_getInstanceFile(user, instanceID)

    combineFile = None
    combineFileName = None # used by euca-register image

    if(transaction['createMode'] == 'ISO'):
        # no combining process, upload instance file directly 
        combineFileName = DEFAULT_IMAGE_NAME
        combineFile = instancePath + combineFileName
        newImageLen = os.path.getsize(combineFile)
        p_updateCombineImageSize(os.path.getsize(combineFile), transactionID)

    else: # transaction['createMode']=='IMG'||transaction['createMode']=='P2V'
        combineFileName = instanceID + '.img'
        combineFile = instancePath + combineFileName
        tmpSize = os.path.getsize(instanceFile) + transaction['imageSize']

        if os.path.exists(combineFile):
            logger.info('combine file %s is already exist, remove it first' % (combineFile))
            os.remove(combineFile)

        p_updateSubmitState(thd_SubmitState.COMBINING, transactionID)
        p_updateSubmitProgress(0, transactionID)
        threadId = combineImage_thread(instanceFile, combineFile)
        threadId.start()
        newImageLen = 0

        #check combine status
        while threadId.isAlive():
            time.sleep(2)
            newImageLen = os.path.getsize(combineFile)
            p_updateCombineImageSize(newImageLen, transactionID)
            logger.info('combine thread alive and new image size is %d' % (newImageLen))
            #update combine status
            combineProgress = int(newImageLen * 100 / tmpSize)
            submitProgress = int(combineProgress / 2)
            if(submitProgress > 50):
                submitProgress = 50
            p_updateSubmitProgress(submitProgress, transactionID)

    #upload image bundle
    p_updateSubmitState(thd_SubmitState.UPLOADING, transactionID)
    p_updateSubmitProgress(51, transactionID)
    p_updateUploadProgress(0, transactionID)

    newImageId = p_create_imageId(instancePath)
    imageSavePath = IMAGE_DEFAULT_PATH+newImageId+'/'
    if not OpenLdap.p_create_walrus_dir(utility.get_ldap_server(),imageSavePath):
        logger.error('p_read_submit_process running create_walrus path is error!')
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1        
    
    #   update upload 
    newImageLen = os.path.getsize(combineFile)
    imageSaveFile = imageSavePath + IMAGE_FILE_NAME

    uploadBoudleThread = p_cloudbot_upload_boudle_thread(transactionID, combineFile,imageSaveFile,instancePath)
    uploadBoudleThread.start()

    preProgress = 0
    progress = 0
    timeout = 0
    logfile = instancePath + 'progress.log'
    while progress < 100 and timeout <= MAXUPLOADTIMES :
        progress = int(p_get_progress(logfile))
        time.sleep(2)
        if progress!=-1:
            submitProgress = 50 + int(progress) * 4 / 10
            p_updateSubmitProgress(submitProgress, transactionID)
            p_updateUploadProgress(progress, transactionID)
            logger.info('upload file progress is :%d' % progress)
        else:
            logger.info('%s is not exist, waiting...' % imageSaveFile)

        if preProgress == progress:
            timeout = timeout + 1
        else:
            timeout = 0
        preProgress = progress
    logger.info('end of p_read_submit_process')

    if timeout > MAXUPLOADTIMES:
        logger.error('upload image time out, force quit')
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1

    if progress < 100:
        logger.error('upload image failed.')
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1
    p_updateUploadProgress(100, transactionID)
    #register new image
    p_updateSubmitState(thd_SubmitState.REGISTERING, transactionID)
    p_updateSubmitProgress(90, transactionID)
    p_updateSubmitEndTime(str(int(time.time())), transactionID)
    p_updateSubmitProgress(99, transactionID)
    p_updateImageToLdap(transactionID, newImageId,newImageLen)

    p_updateSubmitProgress(100, transactionID)
    p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FINISHED, transactionID)
    p_updateSubmitState(thd_SubmitState.FINISHED, transactionID)
    p_releaseTransactionPort(transactionID)

    return 0

def p_get_usbredir_opaque():
    #str = '-device virtserialport,chardev=vdagent,name=com.redhat.spice.0 -readconfig /etc/qemu/ich9-ehci-uhci.cfg '
    str = '-device virtserialport,chardev=vdagent,name=com.redhat.spice.0 '
    str = str + '-device ich9-usb-ehci1,addr=1d.7,multifunction=on,id=ehci0 '
    str = str + '-device ich9-usb-uhci1,addr=1d.0,multifunction=on,id=uhci0-1,masterbus=ehci0.0,firstport=0 '
    str = str + '-device ich9-usb-uhci2,addr=1d.1,multifunction=on,id=uhci0-2,masterbus=ehci0.0,firstport=2 '
    str = str + '-device ich9-usb-uhci3,addr=1d.2,multifunction=on,id=uhci0-3,masterbus=ehci0.0,firstport=4 '
    #str = str + '-device usb-tablet,bus=ehci0.0,port=1,id=t1 ' 
    str = str + '-device ich9-usb-ehci1,addr=1c.7,multifunction=on,id=ehci1 '
    str = str + '-device ich9-usb-uhci1,addr=1c.0,multifunction=on,id=uhci1-1,masterbus=ehci1.0,firstport=0 '
    str = str + '-device ich9-usb-uhci2,addr=1c.1,multifunction=on,id=uhci1-2,masterbus=ehci1.0,firstport=2 '
    str = str + '-device ich9-usb-uhci3,addr=1c.2,multifunction=on,id=uhci1-3,masterbus=ehci1.0,firstport=4 '
    #str = str + '-device usb-tablet,bus=ehci1.0,port=1,id=t2 ' 

    str = str + '-chardev spicevmc,name=usbredir,id=urcd1 -device usb-redir,chardev=urcd1,id=urd1,bus=ehci0.0,port=1 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd2 -device usb-redir,chardev=urcd2,id=urd2,bus=ehci0.0,port=2 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd3 -device usb-redir,chardev=urcd3,id=urd3,bus=ehci0.0,port=3 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd4 -device usb-redir,chardev=urcd4,id=urd4,bus=ehci0.0,port=4 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd5 -device usb-redir,chardev=urcd5,id=urd5,bus=ehci0.0,port=5 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd6 -device usb-redir,chardev=urcd6,id=urd6,bus=ehci0.0,port=6 '
    
    str = str + '-chardev spicevmc,name=usbredir,id=urcd7 -device usb-redir,chardev=urcd7,id=urd7,bus=ehci1.0,port=1 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd8 -device usb-redir,chardev=urcd8,id=urd8,bus=ehci1.0,port=2 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd9 -device usb-redir,chardev=urcd9,id=urd9,bus=ehci1.0,port=3 '
    str = str + '-chardev spicevmc,name=usbredir,id=urcd10 -device usb-redir,chardev=urcd10,id=urd10,bus=ehci1.0,port=4 '
    return str

# p_submitImageThread
class p_submitImageThread(threading.Thread):
    "p_submitImageThread"

    def __init__(self, transactionID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID

    def run(self):
        logger.info('p_submitImageThread start...')
        ret = p_submitImageThread_job(self.transactionID)
        if(ret):
            logger.error('p_submitImageThread_job error')
            p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
            p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
            return False
        return True

# p_submitImage
def p_submitImage(transactionID):
    "p_submitImage"
    if not p_is_resource_available():
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1

    transaction = p_getTransactionStatus(transactionID)
    insId = None
    if transaction['instanceID'] != None:
        insId = transaction['instanceID']
    else:
        return -1
    user = transaction['user']

    #calculate image total size before its submitting
    totalLen = os.path.getsize(p_getInstanceFile(user, insId))
    if(transaction['createMode'] == 'IMG' or transaction['createMode'] == 'P2V'):
        totalLen += transaction['imageSize']

    walrusFreeDisk = OpenLdap.get_walrus_free_disk(utility.get_ldap_server())
    logger.info('p_submitImage : the walrus free disk is %s MB' % (str(walrusFreeDisk)))

    if(walrusFreeDisk < totalLen / MILLION_BYTE + RESERVE_DISK):
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        logger.error('p_submitImage error: the walrus free disk is too lower')
        return -1

    try:
        submitImage = p_submitImageThread(transactionID)
        submitImage.start()
        logger.info('submit image success')
        return 0
    except:
        logger.error('error: submit image failed')
        p_updateTransactionState(thd_TRANSACT_STATE.SUBMIT_FAILED, transactionID)
        p_updateSubmitState(thd_SubmitState.FAILED, transactionID)
        return -1

# luhya_res_setNewImageInfo
def p_setNewImageInfo(transactionID, newImageInfo):
    logger.info('p_setNewImageInfo %s' % (transactionID))
    logger.info('newImageInfo: %s' % str(newImageInfo))
    if newImageInfo == None:
        return False
    imageInfo = {}
    if transactions.has_key(transactionID):
        switch.acquire()

        if newImageInfo.imageOwnerId != None:
            transactions[transactionID]['newImageInfo']['imageOwnerId'] = newImageInfo.imageOwnerId
        else:
            transactions[transactionID]['newImageInfo']['imageOwnerId'] = 'admin'

        if newImageInfo.architecture != None:
            transactions[transactionID]['newImageInfo']['architecture'] = newImageInfo.architecture
        else:
            transactions[transactionID]['newImageInfo']['architecture'] = 'x86_64'

        if newImageInfo.imageType != None:
            transactions[transactionID]['newImageInfo']['imageType'] = newImageInfo.imageType
        else:
            transactions[transactionID]['newImageInfo']['imageType'] = 'Desktop'
        if newImageInfo.name != None:
            transactions[transactionID]['newImageInfo']['name'] = newImageInfo.name
        else:
            transactions[transactionID]['newImageInfo']['name'] = newImageInfo.imageId

        if newImageInfo.imageCategory != None:
            transactions[transactionID]['newImageInfo']['imageCategory'] = newImageInfo.imageCategory
        else:
            transactions[transactionID]['newImageInfo']['imageCategory'] = 0

        if newImageInfo.description != None:
            transactions[transactionID]['newImageInfo']['description'] = newImageInfo.description
        else:
            transactions[transactionID]['newImageInfo']['description'] = 'no description'

        if newImageInfo.platform != None:
            transactions[transactionID]['newImageInfo']['platform'] = newImageInfo.platform
        else:
            transactions[transactionID]['newImageInfo']['platform'] = 'windows'

        if newImageInfo.ownerName != None:
            transactions[transactionID]['newImageInfo']['ownerName'] = newImageInfo.ownerName
        else:
            transactions[transactionID]['newImageInfo']['ownerName'] = 'admin'

        if newImageInfo.vmStyle != None:
            transactions[transactionID]['newImageInfo']['vmStyle'] = newImageInfo.vmStyle
        else:
            transactions[transactionID]['newImageInfo']['vmStyle'] = 'm1.small'

        if newImageInfo.OS != None:
            transactions[transactionID]['newImageInfo']['OS'] = newImageInfo.OS
        else:
            transactions[transactionID]['newImageInfo']['OS'] = 'windows'

        if newImageInfo.HYPERVISOR != None:
            transactions[transactionID]['newImageInfo']['HYPERVISOR'] = newImageInfo.HYPERVISOR
        else:
            transactions[transactionID]['newImageInfo']['HYPERVISOR'] = 'kvm'

        switch.release()
        return True
    return False


def p_get_allow_resource():
    return OpenLdap.get_make_image_resource(utility.get_ldap_server())


def p_is_resource_available():
    hasResource = False
    switch.acquire()
    usedResource = 0
    for tid in transactions.keys():
        if(tid != 'error'):
            transaction = transactions[tid]
            if(transaction['state'] == thd_TRANSACT_STATE.PENDING or\
               transaction['state'] == thd_TRANSACT_STATE.DOWNLOADING or\
               transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FINISHED or\
               transaction['state'] == thd_TRANSACT_STATE.RUNNING or\
               transaction['state'] == thd_TRANSACT_STATE.SHUTTING_DOWN or\
               transaction['state'] == thd_TRANSACT_STATE.SUBMITTING ):
                usedResource = usedResource + 1
    switch.release()
    maxResource = p_get_allow_resource()
    if(usedResource < maxResource):
        hasResource = True
    return hasResource

def p_euca_is_resource_available(transactionID):          # the node is or not to run the instance
    ret = True
    transaction = p_euca_get_transaction(transactionID)
    clientData = transaction['clientData']
    hdSource = utility.utility_get_current_resource()
    if _is_local_node():
        if hdSource!=None:
            if hdSource.cpu_num<1 or hdSource.free_memory-VM_MEMERY<0:
                ret = False
        else:
            ret = False
    else:
        if clientData!=None:
            if hdSource.cpu_num<clientData.vm_info.vm_cpu or hdSource.free_memory-VM_MEMERY<clientData.vm_info.vm_memory:
                ret = False
    return ret

def p_runInstanceByBaseImage(transactionID):
    transaction = p_getTransactionStatus(transactionID)
    ldap_ip = utility.get_ldap_server()
    if(transaction['createMode'] == 'ISO'):
        if not OpenLdap.is_feature_can_use(ldap_ip,FEATURE_IMAGE_BY_ISO):
            return -6
    if(transaction['createMode'] == 'P2V'):
        if not OpenLdap.is_feature_can_use(ldap_ip,FEATURE_IMAGE_BY_P2V):
            return -7
    if not p_is_resource_available():
        p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return -1
    try:
        submitImage = p_runInstanceByBaseImageThread(transactionID)
        submitImage.start()
        return 0
    except:
        p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return -2

#class for starting a instance running thread
class p_euca_run_instance_thread(threading.Thread):
    def __init__(self, transactionID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID

    def run(self):
        logger.info('p_euca_run_instance_thread start...')
        return p_euca_run_instance_thread_job(self.transactionID)

def _get_extern_disk():
    
    # get ext disk file from walrus
    path_is_exist = False
    if not os.path.exists(EXT_DISK_NODE):         
        try:
            os.makedirs(EXT_DISK_NODE)
            path_is_exist=True
        except:
            pass
    else:
        path_is_exist=True

    if path_is_exist:
        ldap_ip =  utility.get_ldap_server()       
        hostip, port = OpenLdap.get_walrus_info(ldap_ip)
        if hostip != None:
#           cmd = 'rsync -r --bwlimit=6144 '+ hostip + ':' + EXT_DISK_WALRUS + ' ' + EXT_DISK_NODE 
            cmd_line='wget -c -t 30 --limit-rate=5120k http://'+hostip+EXT_DISK_WALRUS+EXT_DISK_FILE+' -O '+EXT_DISK_NODE+EXT_DISK_FILE
            cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
            logger.debug(cmd_output)
        else:
            logger.error("get walrus ip is error!")
    else:
        logger.error("create path %s is error !" %EXT_DISK_NODE)


def _get_counterpart():
    return True

#cache image before running an instance. called by p_euca_run_instance_thread
def p_euca_run_instance_thread_job(transactionID):
    transaction = p_euca_get_transaction(transactionID)                                       # get transaction according transactionID
    if transaction == None:                                                                   # instance id not exist
        logger.error('p_euca_run_instance_thread_job: can not find transaction ' + transactionID)
        return RET_ERROR
    else:
        clientData = transaction['clientData']
        user = clientData.user
        imageID = clientData.image_id

        #try to cache image...	
        if (transaction['state'] == thd_TRANSACT_STATE.INIT)\
           or (transaction['state'] == thd_TRANSACT_STATE.DOWNLOAD_FAILED)\
           or (transaction['state'] == thd_TRANSACT_STATE.TERMINATED)\
           or (transaction['state'] == thd_TRANSACT_STATE.RUN_FAILED)\
           or (transaction['state'] == thd_TRANSACT_STATE.DOWNLOADING):
            haveError = False
            isDownloadFinished = False
            
            #get and create image cache path
            logger.info('target image id  is: %s' % (imageID))
            ncInsCachePath = p_getImageMakingCachePath(imageID)                          # get Make Image Instance Cache Path
            if not os.path.exists(ncInsCachePath):
                try:
                    os.makedirs(ncInsCachePath)
                except:
                    log_file = 'Create ' + ncInsCachePath + ' failed!'
                    loggging.error(log_file)
                    p_updateTransactionState(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
                    return RET_ERROR
            logger.info('cache path is: %s' % (ncInsCachePath))

            #cache base image...
            imageLen = clientData.image_size
            isExist = p_isImageExist(ncInsCachePath, imageLen)
            if isExist == False:
                logger.info('image has not been cached on this node, downloading image %s' % (imageID))
                p_euca_update_transaction_state(thd_TRANSACT_STATE.DOWNLOADING, transactionID)

                #check if there is any other transaction has already started to cache the same image.
                isOtherDownloading = False
                switch.acquire()
                for tid in euca_transactions.keys():
                    if(tid != 'error'):
                        trans = euca_transactions[tid]
                        otherClientData = trans['clientData']
                        if(otherClientData.image_id == imageID):
                            if(trans['downloadProgress'] >= 0 and trans['downloadProgress'] < 100):
                                isOtherDownloading = True
                                break
                switch.release()

                #cache image on this node 
                if(not isOtherDownloading):
                    logger.info('downloading the image %s' % (imageID))
                    processid = p_downloadBaseImageThread(imageID, imageLen)
                    processid.start()

                #monitor cache status	
                downloadProgress_pre = 0
                p_euca_update_downloadProgress(downloadProgress_pre, transactionID)
                times = 0
                while  True:
                    time.sleep(3)
                    downloadProgress = p_get_image_download_state(imageID, imageLen)
                    logger.info('download progress %d' % (downloadProgress))
                    if downloadProgress > 100:
                        isDownloadFinished = False
                        haveError = True
                        break
                    if downloadProgress == 100:
                        isDownloadFinished = True
                        break

                    if downloadProgress_pre == downloadProgress:
                        times = times + 1
                    else:
                        times = 0

                    if times > MAXTIMES:
                        haveError = True;
                        break;
                    downloadProgress_pre = downloadProgress
                    p_euca_update_downloadProgress(downloadProgress_pre, transactionID)
                if haveError:
                    p_euca_update_transaction_state(thd_TRANSACT_STATE.DOWNLOAD_FAILED, transactionID)
                    p_euca_update_downloadProgress(-1, transactionID)
                    processid.stop()
            
            logger.info('end of image download')
            # get extern disk file
            if not os.path.exists(EXT_DISK_NODE+EXT_DISK_FILE):
                _get_extern_disk()
            # get domain counterpart
            _get_counterpart()
            #run instance of base image
            if isExist or isDownloadFinished:
                logger.info('image has been successfully cached, try to run...')
                p_euca_update_downloadProgress(100, transactionID)
                p_euca_update_transaction_state(thd_TRANSACT_STATE.DOWNLOAD_FINISHED, transactionID)

                runThread = p_euca_real_run_instance_thread(transactionID)
                runThread.start()
    return 0

def p_euca_get_transaction_id(clientData):
    userName = clientData.user
    imageId = clientData.image_id

    transactionID = None
    switch.acquire()
    for tid in euca_transactions.keys():
        transaction = euca_transactions[tid]
        if transaction['user'] == userName and transaction['imageID'] == imageId:
            transactionID = transaction['transactionID']
            break
    switch.release()
    return transactionID

# if the instance is run , get the instance password and port
def p_get_instance_port_password(instanceId):       
    cmd_line = 'ps -ef |grep kvm |grep '+instanceId    
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    passwd = None
    strPort = None
    if cmd_status==0:
        lines = cmd_output.split('-spice ')
        if len(lines)>0:
            strRes = lines[1]
            rets = strRes.split(' ')
            if len(rets)>0:
                strSpice = rets[0]
                rets = 	strSpice.split(',')
                if len(rets)>0:
                    ports = rets[0].split('=')
                    passwds = rets[1].split('=')
                    if len(ports)>0:
                        strPort = ports[1]
                    if len(passwds)>0:
                        passwd = passwds[1]
    logger.info('the instance port and password is:%s' %(instanceId+':'+strPort +','+passwd))
    return strPort,passwd


def p_euca_run_instance(transactionID):
    logger.info('p_euca_run_instance %s' % transactionID)
    
    #try to comfirm this instance has a valid vm config record on registry server.	
    transaction = p_euca_get_transaction(transactionID)
    if transaction==None:
        logger.error('p_euca_run_instance: can not find tansaction' )
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return RET_CREATE_FAILED
    
    p_euca_update_transaction_state(thd_TRANSACT_STATE.DOWNLOADING, transactionID)#Should be Downloading , or still stays init status ??
    clientData = transaction['clientData']
    if clientData == None:
        logger.error('p_euca_run_instance: can not find client data to run instance' )
        return RET_ERROR	
        #should continue to get vmconfig data when clientdata is missing ??
        #vmconfigID = transaction['vmconfigID']
        #vmconfig = thd_vmConfig()
        #if vmconfigID==None:
        #    vmconfig = OpenLdap.get_vmconfig_by_user_image(transaction['user'], transaction['imageID'])
        #else:
        #     ldap_ip = utility.get_ldap_server()
        #    vmconfig = OpenLdap.get_vmConfig_by_id(ldap_ip,vmconfigID)
        #if(vmconfig == None or vmconfig.id==None):
        #    logger.error('p_euca_run_instance: can not find any client data or vmconfig record' )    
        #    p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        #return -5
        #logger.info(str(vmconfig))
        
    #now try to run the instance...  
    instanceID = transaction['instanceID']	
    insStatus = p_getInstanceState(instanceID)
    #instance is already runnning
    if (insStatus != None) and (insStatus == 'running'):
        sPort,passwd = p_get_instance_port_password(instanceID)      
        transaction['instancePort'] = int(sPort)
        transaction['instancePassword'] = passwd
        #should also update instance info in clientData here ??
        #todo...		
        p_euca_update_downloadProgress(100, transactionID)
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUNNING, transactionID)
        return RET_OK
    #instance is not exist, run it in a new thread	
    
    #first, try to comfirm there are enough resouces available for this instance running on current node 
    if not p_euca_is_resource_available(transactionID):
        logger.error('p_euca_run_instance: no enough resource to run' )
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return RET_NO_RESOURCE

    try:
        runIns = p_euca_run_instance_thread(transactionID)
        runIns.start()
        return RET_OK
    except:
        logger.error('p_euca_run_instance: instance running exception' )
        p_euca_update_transaction_state(thd_TRANSACT_STATE.RUN_FAILED, transactionID)
        return RET_RUN_FAILED

class p_runInstanceByBaseImageThread(threading.Thread):
    def __init__(self, transactionID):
        threading.Thread.__init__(self)
        self.transactionID = transactionID

    def run(self):
        logger.info('p_runInstanceByBaseImageThread start...')
        return p_runInstanceByBaseImageThread_job(self.transactionID)


def p_set_instance_boot_from(transactionID, bootFrom):
    res = False
    switch.acquire()
    transaction = p_getTransactionStatus(transactionID)
    if(transaction != None):
        transaction['bootFrom'] = bootFrom
        res = True
    switch.release()
    return res


def p_restore_instance(userName, imageID):
    logger.info('p_restore_instance(%s)' % (userName+' '+imageID))
    is_restore = False
    g_restore_switch.acquire()
    if g_restore_transaction['userName']!=None:
       if g_restore_transaction['state']!=None and g_restore_transaction['state']=='RESTORING' :
           is_restore = True   
    if not is_restore :
        g_restore_transaction['state'] = 'RESTORING'
        g_restore_transaction['instanceID'] = None       
        g_restore_transaction['progress'] = -1
        g_restore_transaction['imageID'] = imageID
        g_restore_transaction['userName'] = userName
        logger.info('p_restore_instance create thread ')         
        restoreThread = p_restore_instance_thread(userName,imageID)
        g_restore_transaction['threadID'] = restoreThread
        restoreThread.start()
        logger.info('p_restore_instance:%s' %str(g_restore_transaction))
    g_restore_switch.release()
    return True

def p_backup_instance(userName,imageID):
    logger.info('p_backup_instance(%s)' % (userName+' '+imageID))
    is_backup = False
    g_backup_switch.acquire()
    if g_backup_transaction['userName']!=None:
       if g_backup_transaction['state']!=None and g_backup_transaction['state']=='DUPLICATING' :
           is_backup = True 
    logger.info('p_backup_instance( the tran: %s)' % str(g_backup_transaction))  
    if not is_backup :
        g_backup_transaction['state'] = 'DUPLICATING'
        g_backup_transaction['instanceID'] = None       
        g_backup_transaction['progress'] = -1
        g_backup_transaction['imageID'] = imageID
        g_backup_transaction['userName'] = userName         
        backupThread = p_backup_instance_thread(userName,imageID)
        logger.info('p_backup_instance( get p_backup_instance_thread)' )
        g_backup_transaction['threadID'] = backupThread
        backupThread.start()
    g_backup_switch.release()
    return True

def p_stop_backup_instance(userName,imageID):
    g_backup_switch.acquire()
    if g_backup_transaction['userName']!=None and g_backup_transaction['imageID']!=None and g_backup_transaction['userName']==userName and g_backup_transaction['imageID']==imageID :
        if g_backup_transaction['threadID'].isAlive():
            g_backup_transaction['threadID'].stop()
        g_backup_transaction['state'] = None
        g_backup_transaction['instanceID'] = None       
        g_backup_transaction['progress'] = -1
        g_backup_transaction['imageID'] = None
        g_backup_transaction['userName'] = None
        g_backup_transaction['threadID'] = None
    g_backup_switch.release()
    return True
 
def p_get_backup_time(userName, imageID):
    time = 0
    instanceId = (imageID[4:len(imageID)] + userName)[0:15]
    backup_ins_path = BACKUP_ROOT_PATH+'instances/'+userName+'/'+instanceId+'/'
    backup_ins_file = backup_ins_path+'machine'
    backup_cache_path = BACKUP_ROOT_PATH+'caches/'
    backup_cache_file = backup_cache_path+imageID+'/machine'
    if os.path.exists(backup_ins_file):
        stat = os.stat(backup_ins_file) 
        time = stat.st_mtime
    else:
        if os.path.exists(backup_cache_file):
            stat = os.stat(backup_cache_file) 
            time = stat.st_mtime
    info = 	'userName: '+userName+'imageID: '+imageID+'bachuptime: '+str(time)				
    logger.info('p_get_backup_time :%s' % info)
    return time        
        
def p_get_file_length( fileName):
    len = -1
    stat = os.stat(fileName)
    if(stat!=None):
        len = stat.st_size
    return len        

def p_move_file(srcFile,decFile):
    cmd = 'mv ' + srcFile + ' ' + decFile
    cmd_status, cmd_output = commands.getstatusoutput(cmd)
    logger.info('p_move_file cmd_output:%s' % str(cmd_output))
    if cmd_status:
        logger.error('p_move_file  error')
        return -1
    return 0    

def p_chage_file_mode(fileName):
    cmd = 'sudo chmod 777 '+ fileName   
    cmd_status, cmd_output = commands.getstatusoutput(cmd)
    logger.info('p_chage_file_mode cmd_output:%s' % str(cmd_output))
    if cmd_status:
        logger.error('p_chage_file_mode  error')
        return -1
    return 0
    
class p_backup_instance_thread(threading.Thread):
    def __init__(self,userName,imageID):
        threading.Thread.__init__(self)
        self.userName = userName
        self.imageID = imageID
        self.isTerminate = False
    def run(self):
        ldap_ip =  utility.get_ldap_server()   
        clc_ip = OpenLdap.get_clc_ip(ldap_ip)
        
        instanceId = (self.imageID[4:len(self.imageID)] + self.userName)[0:15]
        logger.info('p_backup_instance_thread  backup ins: %s' % instanceId)
        
        backup_total_len = 0
        backup_cache_path = BACKUP_ROOT_PATH+'caches/'+self.imageID+'/'
        backup_cache_file = backup_cache_path+'machine'
        logger.info('p_backup_instance_thread  backup path: %s' % backup_cache_file)
        
        if not os.path.exists(backup_cache_path):
            try:
                os.makedirs(backup_cache_path)
            except:
                OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
                return
        ins_cache_file = p_getCacheFile(self.imageID)
        logger.info('p_backup_instance_thread  ins_cache_file: %s' % ins_cache_file)
        if not os.path.exists(ins_cache_file):
            g_backup_switch.acquire()
            g_backup_transaction['state'] = 'BACKUP_FAILED'
            g_backup_switch.release()
            logger.info('p_backup_instance_thread: the instance never run : %s' % self.userName+' '+self.imageID)
            OpenLdap.p_set_backup_state(clc_ip, self.userName , self.imageID , 'BACKUP_FAILED')
            return
        if not os.path.exists(backup_cache_file):
            if os.path.exists(ins_cache_file): 
                backup_total_len =backup_total_len+ p_get_file_length( ins_cache_file)
        logger.info('p_backup_instance_thread  backup_total_len: %s' % str(backup_total_len))
        ins_instance_file =  p_getInstanceFile( self.userName,instanceId)
        logger.info('p_backup_instance_thread  ins_instance_file: %s' % ins_instance_file)
        if os.path.exists(ins_instance_file):
            backup_total_len =backup_total_len+ p_get_file_length( ins_instance_file)
        logger.info('p_backup_instance_thread  1')	
        progress = 0
        is_backup_error = False
        logger.info('p_backup_instance_thread  2')
        if not os.path.exists(backup_cache_file) and os.path.exists(ins_cache_file):
#            p_chage_file_mode(ins_cache_file)
            fSource = open(ins_cache_file, 'rb')
            logger.info('p_backup_instance_thread  ins_cache_file: %s' % ins_cache_file)
            try:  
                fSource.seek (0) 
                isBackupOver = False
                wrFile = backup_cache_path+'machine.tmp'      
                if(os.path.exists(wrFile)):
                    os.remove(wrFile)			
                fDest = open(wrFile, 'a')
                try:
                    writelen = 0				
                    while True:
                        if self.isTerminate:
                            break 
                        buffer = fSource.read(BUFF_LEN)                       
                        if not buffer:
                            # mv filer
                            isBackupOver = True                          
                            break
                        fDest.write(buffer)
                        writelen=writelen+BUFF_LEN
                        if writelen>backup_total_len:
                            writelen = backup_total_len
                        backup_cache_progress = int(writelen*100/backup_total_len)
                        if backup_cache_progress > progress :
                            progress = backup_cache_progress
                            logger.info('p_backup_instance_thread  progress: %s' % str(progress))
                            OpenLdap.p_set_backup_progress( clc_ip,self.userName,self.imageID,backup_cache_progress)                
                except Exception:
                    is_backup_error = True
                    g_backup_switch.acquire()
                    g_backup_transaction['state'] = 'BACKUP_FAILED'
                    g_backup_switch.release()
                    logger.error('p_backup_instance_thread  write file error' )
                    OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
                fDest.close()
                if isBackupOver:
                    p_move_file(wrFile,backup_cache_file)
            except Exception:
                is_backup_error = True
                g_backup_switch.acquire()
                g_backup_transaction['state'] = 'BACKUP_FAILED'
                g_backup_switch.release()
                OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
            fSource.close()
        if is_backup_error:
            OpenLdap.p_set_backup_state(clc_ip,  self.userName,self.imageID,'BACKUP_FAILED')
            return
        backup_ins_path = BACKUP_ROOT_PATH+'instances/'+self.userName+'/'+instanceId+'/'
        backup_ins_file = backup_ins_path+'machine'
        if not os.path.exists(backup_ins_path):
            try:
                os.makedirs(backup_ins_path)
            except:
                g_backup_switch.acquire()
                g_backup_transaction['state'] = 'BACKUP_FAILED'
                g_backup_switch.release()
                OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
                return

        if os.path.exists(ins_instance_file):       
            fSource = open(ins_instance_file, 'rb')
            try:  
                fSource.seek (0) 
                wrFile = backup_ins_path+'machine.tmp'
                isBackupOver = False      
                if(os.path.exists(wrFile)):
                    os.remove(wrFile)			
                fDest = open(wrFile, 'a')
                try:
                    writelen = 0				
                    while True:
                        if self.isTerminate:
                            break   
                        buffer = fSource.read(BUFF_LEN)                       
                        if not buffer:
                            #mv file
                            isBackupOver = True
                            g_backup_switch.acquire()
                            g_backup_transaction['state'] = 'BACKUP_FINISH'
                            g_backup_switch.release()							
                            OpenLdap.p_set_backup_state(clc_ip,  self.userName,self.imageID,'BACKUP_FINISH')
                            break
                        fDest.write(buffer)
                        writelen=writelen+BUFF_LEN
                        if writelen>backup_total_len:
                            writelen = backup_total_len
                        backup_cache_progress = int(writelen*100/backup_total_len)
                        if backup_cache_progress > progress :
                            progress = backup_cache_progress
                            OpenLdap.p_set_backup_progress(clc_ip, self.userName,self.imageID,backup_cache_progress)                
                except Exception:
                    OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
                    g_backup_switch.acquire()
                    g_backup_transaction['state'] = 'BACKUP_FAILED'
                    g_backup_switch.release()
                fDest.close()
                if isBackupOver:
                    p_move_file(wrFile,backup_ins_file)
            except Exception:
                OpenLdap.p_set_backup_state(clc_ip, self.userName,self.imageID,'BACKUP_FAILED')
                g_backup_switch.acquire()
                g_backup_transaction['state'] = 'BACKUP_FAILED'
                g_backup_switch.release()
            fSource.close()
        
    def stop(self):
        self.isTerminate = True

def p_restore_file(userName,imageID):
    logger.info('p_restore_file start ')
    
    ldap_ip =  utility.get_ldap_server()   
    clc_ip = OpenLdap.get_clc_ip(ldap_ip)

    instanceId = (imageID[4:len(imageID)] + userName)[0:15]
    ins_instance_file =  p_getInstanceFile(userName,instanceId)
    backup_ins_path = BACKUP_ROOT_PATH+'instances/'+userName+'/'+instanceId+'/'
    backup_ins_file = backup_ins_path+'machine'
    
    logger.info('p_restore_instance_thread  backup_ins_file:%s ' % backup_ins_file)
    logger.info('p_restore_instance_thread  ins_instance_file:%s ' % ins_instance_file)
    
    if not os.path.exists(backup_ins_file):
        if(os.path.exists(ins_instance_file)):
            os.remove(ins_instance_file)            
    else:  
        backup_total_len = p_get_file_length( backup_ins_file)
        logger.info('p_restore_file len:%d ' % backup_total_len)
        progress = 0     
        fSource = open(backup_ins_file, 'rb')
        logger.info('p_restore_file len: open backup file ')
        try:  
            fSource.seek(0) 
            wrFile = p_getImageMakingInstancePath(userName, instanceId)+'machine.tmp'
            if(os.path.exists(wrFile)):
                os.remove(wrFile)			
            fDest = open(wrFile, 'a')
            isRestoreOver = False
            try:
                writelen = 0				
                while True: 
                    buffer = fSource.read(BUFF_LEN)
                    if not buffer:
                        #mv file
                        isRestoreOver = True
                        g_restore_switch.acquire()
                        g_restore_transaction['state'] = 'RESTORE_FINISH'
                        g_restore_switch.release()
                        OpenLdap.p_set_restore_state(clc_ip, userName,imageID,'RESTORE_FINISH')
                        break
                    fDest.write(buffer)
                    writelen=writelen+BUFF_LEN
                    if writelen>backup_total_len:
                        writelen = backup_total_len
                    restore_progress = int(writelen*100/backup_total_len)
                    if restore_progress > progress :
                        progress = restore_progress
                        logger.info('p_restore_instance_thread  progress:%d' % progress)
                        OpenLdap.p_set_restore_progress( clc_ip,  userName,imageID,restore_progress)                
            except Exception:
                OpenLdap.p_set_restore_state(clc_ip, userName,imageID,'RESTORE_FAILED')
                g_restore_switch.acquire()
                g_restore_transaction['state'] = 'RESTORE_FAILED'
                g_restore_switch.release()
            fDest.close()
            if isRestoreOver:
                p_move_file(wrFile,ins_instance_file)
        except Exception:
            OpenLdap.p_set_restore_state(clc_ip, userName,imageID,'RESTORE_FAILED')
            g_restore_switch.acquire()
            g_restore_transaction['state'] = 'RESTORE_FAILED'
            g_restore_switch.release()
        fSource.close()

class p_restore_instance_thread(threading.Thread):
    def __init__(self,userName,imageID):
        threading.Thread.__init__(self)
        self.userName = userName
        self.imageID = imageID

    def run(self):   
        p_restore_file(self.userName,self.imageID)
              

def p_attach_iso(isoFile , transactionID):
    if(isoFile == None or transactionID == None):
        return False
    instanceID = transactions[transactionID]['instanceID']
    xml = p_generate_attach_iso_xml(isoFile)
    ret = p_attach_iso_by_domain(xml,instanceID)
    if (ret == -1):
        return False
    return True

# p_attach_iso_by_domain
def p_attach_iso_by_domain(xml,domain):
    logger.info("p_attach_iso_by_domain ...")
    logger.info(xml)
    ret = -1
    if (xml == None or domain == None):
        return -1
    try:
        logger.info('attach try start')

        xmlFile = '/tmp/attachiso.xml'
        if p_write_file(xmlFile,xml):
            cmd_line = 'virsh attach-device '+domain+' '+xmlFile
            logger.info('live backup  cmd_line:%s'%cmd_line+' ')
            g_virsh_command_lock.acquire()
            cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
            g_virsh_command_lock.release()
            if cmd_status==0 :
                ret = 0
            else:
                ret = -1
        logger.info('attach iso success! %s'%cmd_line+' ')

    except:
        logger.error('attach iso failed! %s'%cmd_line+' ')
       
    return ret
    
# p_generate_attach_iso_xml templet
def p_generate_attach_iso_xml(isoFile):
    xml = ''
    doc = Document()
   
    disk = doc.createElement('disk')
    disk.setAttribute('type','file')
    disk.setAttribute('device', 'cdrom')
    
    source = doc.createElement('source')
    source.setAttribute('file',ISO_FILE_PATH + isoFile + '.' + ISO_EXTERN_NAME)   # add the iso to cdrom 
    disk.appendChild(source)
    
    target = doc.createElement('target')
    target.setAttribute('dev', 'hdc')
    target.setAttribute('bus', 'ide')
    disk.appendChild(target)
    
    doc.appendChild(disk)
    xml = doc.toxml()
    return xml


def p_is_service_start():
    serviceName = CLOUD_NC
    return utility.p_is_service_start(serviceName)

def p_start_service():
    serviceName = CLOUD_NC
    return utility.p_start_service(serviceName)
    
def p_stop_service():
    serviceName = CLOUD_NC
    return utility.p_stop_service(serviceName)

def p_instance_is_running(instanceID):
    ret= False
    logger.info('p_instance_is_running(%s)' % instanceID)
    cmd_line = 'virsh list | grep instanceID'
    cmd_line = cmd_line.replace('instanceID', instanceID)
    logger.info('p_instance_is_running : ' + cmd_line)
    g_virsh_command_lock.acquire()
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    g_virsh_command_lock.release()
    if ((cmd_status == 0) and (cmd_output.find(instanceID) != -1)):
        ret = True
    logger.info('p_instance_is_running cmd_output %s' % str(cmd_output))
    return ret

def p_instance_is_running(user,imageId):
    ret= False
    logger.info('p_instance_is_running(%s)' % user+' '+imageId+' ')
    instanceID = (imageId[4:len(imageId)] + user)[0:15]
    cmd_line = 'virsh list | grep instanceID'
    cmd_line = cmd_line.replace('instanceID', instanceID)
    logger.info('p_instance_is_running : ' + cmd_line)
    g_virsh_command_lock.acquire()
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    g_virsh_command_lock.release()
    if ((cmd_status == 0) and (cmd_output.find(instanceID) != -1)):
        ret = True
    logger.info('p_instance_is_running cmd_output %s' % str(cmd_output))
    return ret
      
def p_add_migrage_transaction(transaction):
    logger.info('handle p_add_migrage_transaction ' )
    if(transaction == None or transaction.transactionID == None):
        return False
    logger.info('p_add_instance_transaction:%s '%transaction)
    transactionInfo = {}
    transactionInfo['transactionID'] = transaction.transactionID
    transactionInfo['imageID'] = transaction.imageID
    transactionInfo['state'] = thd_TRANSACT_STATE.INIT
    transactionInfo['instanceID'] = transaction.instanceID
    transactionInfo['instancePort'] = transaction.instancePort
    transactionInfo['instancePassword'] = transaction.instancePassword
    transactionInfo['downloadProgress'] = transaction.downloadProgress
    transactionInfo['imageSize'] = transaction.imageSize
    transactionInfo['user'] = transaction.user
    transactionInfo['nodeIp'] = transaction.nodeIp
    transactionInfo['modifyTime'] = transaction.modifyTime
    euca_transactions[transaction.transactionID] = transactionInfo
    
    instanceFile = p_getInstanceFile(transaction.user, transaction.instanceID)
    dumpFile = p_get_restore_dump_file(instanceFile)
    if dumpFile!=None and os.path.isfile(dumpFile):
        g_auto_migrate_state_switch.acquire()
        g_auto_migrate_state_lists[transaction.user+transaction.imageID] = True
        g_auto_migrate_state_switch.release()
        p_euca_run_instance(transaction.transactionID)
    return True        
     	
def p_live_migrage_domains(migrageLists):
    logger.info('handle p_live_migrage_domains %s' % (migrageLists))
    if(migrageLists == None):
        return False
    for migrageInfo in migrageLists:
        transactionID = migrageInfo.transactionID
        sourceIP = migrageInfo.sourceIP
        targetIP = migrageInfo.targetIP
        transaction = p_get_run_instance_transaction_byid(transactionID);
        instanceID = transaction.instanceID
        if(instanceID == None or sourceIP == None or targetIP == None):
            continue
        ldap_ip =  utility.get_ldap_server()   
        clc_ip = OpenLdap.get_clc_ip(ldap_ip)
        OpenLdap.p_set_migrage_state(clc_ip, clc_iptransactionID,thd_MIGRATESTATE.MIGRATTING)
        logger.info('p_restore_instance create thread ')         
        migrateThread = p_live_migrage_thread(instanceID,targetIP,transaction)
        migrateThread.start()
    return True
    
 # p_live_migrage_domain
def p_live_migrage(domain,targetIP,transaction):
    logger.info("p_live_migrage ...")
    ret = -1
    if (domain == None or targetIP == None or transaction == None):
        return -1
    
    g_live_migrate_state_switch.acquire()
    g_live_migrate_state_lists[transaction.user+transaction.imageID]=True
    g_live_migrate_state_switch.release()
    ldap_ip =  utility.get_ldap_server()   
    clc_ip = OpenLdap.get_clc_ip(ldap_ip)

    try:
        if(p_live_backup_domain(transaction) == 0):

            transaction.nodeIp = targetIP
            OpenLdap.add_migrage_transaction(targetIP,transaction)
            OpenLdap.p_set_migrage_state(clc_ip, transaction.transactionID,thd_MIGRATESTATE.MIGRATE_FINISHED)
            for i in range(15):
                if OpenLdap.check_instance_is_running(targetIP,transaction.instanceID):
                    break
                time.sleep(2)
            p_euca_stop_instance(transaction.transactionID)
            del euca_transactions[transaction.transactionID]
            logger.info('live migrate success!')
            ret = 0
        else:
            OpenLdap.p_set_migrage_state(clc_ip, transaction.transactionID,thd_MIGRATESTATE.MIGRATE_FAILED)
            logger.error('live migrate failed! ')
    except:
        OpenLdap.p_set_migrage_state(clc_ip, transaction.transactionID,thd_MIGRATESTATE.MIGRATE_FAILED)
        logger.error('live migrate failed! ')
    
    g_live_migrate_state_switch.acquire()
    g_live_migrate_state_lists[transaction.user+transaction.imageID]=False
    g_live_migrate_state_switch.release()
    
    return ret
   
#search the latest dump file for restore 
def p_get_restore_dump_file(instanceFile):
    dumpFile1 = instanceFile+'.state1'
    dumpFile2 = instanceFile+'.state2'
    dumpLog1 = instanceFile+'.state1.log'
    dumpLog2 = instanceFile+'.state2.log'
    dumpFile=None
    bExist1 = os.path.isfile(dumpLog1)
    bExist2 = os.path.isfile(dumpLog2)
    if (bExist1 == True and bExist2 == True):
        if(os.stat(dumpFile1).st_ctime > os.stat(dumpFile2).st_ctime):
            dumpFile = dumpFile1
        else:
            dumpFile = dumpFile2
    elif (bExist1 == True and bExist2 == False):
        dumpFile=dumpFile1
    elif (bExist1 == False and bExist2 == True):
        dumpFile=dumpFile2
    else:
        dumpFile=None
    return dumpFile

#search the oldest file name for backup     
def p_get_backup_dump_file(instanceFile):
    dumpFile1 = instanceFile+'.state1'
    dumpFile2 = instanceFile+'.state2'
    dumpLog1 = instanceFile+'.state1.log'
    dumpLog2 = instanceFile+'.state2.log'
    dumpFile=dumpFile1
    bExist1 = os.path.isfile(dumpLog1)
    bExist2 = os.path.isfile(dumpLog2)
    if (bExist1 == True and bExist2 == True):
        if(os.stat(dumpFile1).st_ctime > os.stat(dumpFile2).st_ctime):
            dumpFile = dumpFile2
        else:
            dumpFile = dumpFile1
    elif (bExist1 == True and bExist2 == False):
        dumpFile=dumpFile2
    elif (bExist1 == False and bExist2 == True):
        dumpFile=dumpFile1
    else:
        dumpFile=dumpFile1
    return dumpFile

 # p_live_backup_domain
def p_live_backup_domain(transaction):
    logger.info("p_live_backup_domain ...%s"%transaction)
    ret = -1
    
    if (transaction == None):
        return -1
    instanceID=transaction.instanceID
    user=transaction.user
    instanceFile = p_getInstanceFile(user, instanceID)
    dumpFile = p_get_backup_dump_file(instanceFile)
    logFile = dumpFile+'.log'
    if(os.path.isfile(dumpFile)):
        os.remove(dumpFile)
    if(os.path.isfile(logFile)):
        os.remove(logFile)
    try:
        logger.info('live backup try start')
        cmd_line = 'virsh dump '+instanceID+' '+dumpFile
        logger.info('live backup  cmd_line:%s'%cmd_line)
        g_virsh_command_lock.acquire()
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        g_virsh_command_lock.release()
        if(cmd_status == 0):
            ret = 0
            p_write_file(logFile,'dump success!')
            logger.info('live backup success! %s'%cmd_line+' '+cmd_output)
        else:
            ret = -1
            logger.error('live backup failed! %s'%cmd_line+' '+cmd_output)
            if(os.path.isfile(dumpFile)):
                os.remove(dumpFile)
    except:
        logger.error('live backup failed!')
        if(os.path.isfile(dumpFile)):
            os.remove(dumpFile)
      
    return ret
    
def p_live_backup():
    logger.info('p_live_backup')
    localip = utility.get_local_publicip()
    try:
        ldap_ip = utility.get_ldap_server()
        migrate_lists = OpenLdap.p_get_migrate_info_list(ldap_ip)
    
        for migrateInfo in migrate_lists:
            migrateInfo.transactionID = p_get_transId_by_user_image(migrateInfo.user,migrateInfo.imageId)
            if(migrateInfo.transactionID ==None):
                continue
            if(localip == migrateInfo.sourceIP or localip == migrateInfo.targetIP):
                transaction = p_get_run_instance_transaction_byid(migrateInfo.transactionID)
                if(transaction != None and transaction.instanceID != None and transaction.state == thd_TRANSACT_STATE.RUNNING):
                    if(g_live_migrate_state_lists.has_key(transaction.user+transaction.imageID)):
                        if(g_live_migrate_state_lists[transaction.user+transaction.imageID]):
                            continue
                    p_live_backup_domain(transaction)
    except Exception,e:
        logger.error('p_live_backup Exception: %s'%e)

def p_auto_migrate_start_vm(migrateInfo):
    logger.info('p_auto_migrate_start_vm:%s'%migrateInfo) 
    if(migrateInfo == None):
        return
    transactionID = p_get_transId_by_user_image(migrateInfo.user,migrateInfo.imageId)
    if(p_instance_is_running(migrateInfo.user,migrateInfo.imageId) == False):
        if(transactionID != None):
            switch.acquire()
            del euca_transactions[transactionID]
            switch.release()
        imgLen=OpenLdap.p_getImageLength(utility.get_ldap_server(),migrateInfo.imageId)
        if(imgLen > 0):
            instanceId = (migrateInfo.imageId[4:len(migrateInfo.imageId)] + migrateInfo.user)[0:15]
            dumpFile = p_getInstanceFile(migrateInfo.user, instanceId)+'.state'
            if os.path.isfile(dumpFile):
                g_auto_migrate_state_switch.acquire()
                g_auto_migrate_state_lists[migrateInfo.user+migrateInfo.imageId] = True
                g_auto_migrate_state_switch.release() 
                transactionID = p_create_run_instance_transaction(clientData)				
                #transactionID = p_create_run_instance_transaction(migrateInfo.imageId, imgLen, instanceId, migrateInfo.user)
                if(transactionID != None):
                    p_euca_run_instance(transactionID)

def p_auto_migrate_start_vm_monitor():
    logger.info('p_auto_migrate_start_vm_monitor:%s'%g_live_vm_lists) 
    localip = utility.get_local_publicip()
    try:
        #ldap_ip = utility.get_ldap_server()
        #migrate_lists = OpenLdap.p_get_migrate_instance_list(ldap_ip)
        g_live_vm_switch.acquire()
        for key in g_live_vm_lists.keys():
            bStart = False
            migrateInfo = g_live_vm_lists[key]
            if((localip == migrateInfo.targetIP and OpenLdap.p_nc_is_live(migrateInfo.sourceIP) == False) or (localip == migrateInfo.sourceIP and OpenLdap.p_nc_is_live(migrateInfo.targetIP) == False)):
                if(migrateInfo.isMigrated == False):
                    bStart = True
                    migrateInfo.isMigrated = True
                    #g_live_vm_lists[migrateInfo.user+migrateInfo.imageId] = migrateInfo
            logger.info('p_auto_migrate_start_vm_monitor bStart = %s'%bStart) 
            if bStart :
                p_auto_migrate_start_vm(migrateInfo)
        #g_live_vm_lists.clear()	
        g_live_vm_switch.release()
    except Exception,e:
        logger.error('p_auto_migrate_start_vm_monitor Exception:'%e) 
    
def p_auto_migrate_receive_vms(migratevmLists):
    logger.info('p_auto_migrate_receive_vms')
    g_live_vm_switch.acquire()
    g_live_vm_lists.clear()
    #add vms on pair node 
    for migrateInfo in migratevmLists:
        migrateInfo.isMigrated=False
        g_live_vm_lists[migrateInfo.user+migrateInfo.imageId]=migrateInfo
    g_live_vm_switch.release()
    logger.info('p_auto_migrate_receive_vms %s: ' % g_live_vm_lists)
    return True
   
def p_get_live_vm_list(migrate_lists):
    logger.info('p_get_live_vm_list')
    vm_list = []
    localip = utility.get_local_publicip()
    try:
        if migrate_lists == None :
            return vm_list
        for migrateInfo in migrate_lists:
           migrateInfo.transactionID = p_get_transId_by_user_image(migrateInfo.user,migrateInfo.imageId)
           bAppend = False
           if((localip == migrateInfo.sourceIP or localip == migrateInfo.targetIP) and migrateInfo.transactionID != None):
               transaction = p_get_run_instance_transaction_byid(migrateInfo.transactionID) 
               if(transaction == None):
                   continue
               if(transaction.nodeIp == localip and (transaction.state == thd_TRANSACT_STATE.PENDING or transaction.state == thd_TRANSACT_STATE.RUNNING)):
                   bAppend = True
           if bAppend :
               vm_list.append(migrateInfo)
    except Exception,e:
        logger.error('p_get_live_vm_list Exception: %s'%e)
    return vm_list

def p_heart_beat_timer():
    global g_cc_ip
    global g_nc_ip
    if g_cc_ip != None and g_nc_ip != None:
        OpenLdap.p_nc_heart_beat(g_cc_ip,g_nc_ip)
    heart = threading.Timer(1.0,p_heart_beat_timer)
    heart.start()

 
def p_send_live_vm_list(vmlist):
    logger.info('p_send_live_vm_list:%s'%vmlist)
    localip = utility.get_local_publicip()
    ldap_ip = utility.get_ldap_server()
    migrate_node_list = OpenLdap.p_get_live_migrate_node_list(ldap_ip)
    for migrateInfo in migrate_node_list:
        if(localip == migrateInfo.sourceIP):
            try:
                OpenLdap.p_nc_auto_migrate_receive_vms(migrateInfo.targetIP,vmlist)
            except:
                logger.error('send live vm lists to  %s failed!'%migrateInfo.targetIP)  
            logger.info('send live vm lists to  %s sucess!'%migrateInfo.targetIP)  
        elif(localip == migrateInfo.targetIP):
            try:
                OpenLdap.p_nc_auto_migrate_receive_vms(migrateInfo.sourceIP,vmlist)
            except:
                logger.error('send live vm lists to  %s failed!'%migrateInfo.sourceIP) 
            logger.info('send live vm lists to  %s sucess!'%migrateInfo.sourceIP)  
        else:
            pass

class p_heart_beat_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_NC,utility.get_local_publicip())
            if ret:
                logger.debug('p_heart_beat_thread start ....')
                p_heart_beat_timer()
                break
            else:
                time.sleep(2)

           
def p_start_migrate_monitor():
    localip = utility.get_local_publicip()
    while True:
        ldap_ip = utility.get_ldap_server()
        ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_NC,localip)
        if ret:
            ldap_ip = utility.get_ldap_server()
            migrate_node_list = OpenLdap.p_get_live_migrate_node_list(ldap_ip)
            bStart = False
            for nodeMigrateInfo in migrate_node_list:
                if(localip == nodeMigrateInfo.sourceIP or localip == nodeMigrateInfo.targetIP):
                    bStart = True
                    break;
            if bStart:	
                auto_migrate_send_monitor = p_auto_migrate_send_monitor_thread()
                auto_migrate_send_monitor.start()
        
                auto_migrate_start_vm_monitor = p_auto_migrate_start_vm_monitor_thread()
                auto_migrate_start_vm_monitor.start()
        
                live_backup_thread = p_live_backup_thread();
                live_backup_thread.start()
        
                logger.info('Starting auto migrate monitor ...')
            break
        else:
            time.sleep(2)
        
class p_auto_migrate_send_monitor_thread(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

    def run(self): 
        ldap_ip = utility.get_ldap_server()
        migrate_lists = OpenLdap.p_get_migrate_info_list(ldap_ip)
        while True:
            #get live vms on current node
            vmlist = p_get_live_vm_list(migrate_lists)
            logger.info('p_auto_migrate_send_monitor_thread vmlist:%s'%vmlist)
            #send live vms to migrate pair node
            if(len(vmlist) > 0):
                p_send_live_vm_list(vmlist)

            #send live vms per 5 second
            time.sleep(5)
        
 
class p_auto_migrate_start_vm_monitor_thread(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

    def run(self):  
        while True:

            #if migrate vm is not running on migrate pair node,start vm on current node
            p_auto_migrate_start_vm_monitor()
            
            #send live vms per 2 second
            time.sleep(1)
            
              
class p_live_backup_thread(threading.Thread):
    def __init__(self,):
        threading.Thread.__init__(self)

    def run(self):  
        while True:
            # live backup per 120 second
            time.sleep(60) 
            p_live_backup()    
            
class p_live_migrage_thread(threading.Thread):
    def __init__(self,domain,targetIP,transaction):
        threading.Thread.__init__(self)
        self.domain = domain
        self.targetIP = targetIP
        self.transaction = transaction

    def run(self):   
        p_live_migrage(self.domain,self.targetIP,self.transaction)
 
'''def p_add_snapshot(snapshotInfo):
    logger.info('p_add_snapshot')
    if snapshotInfo == None or snapshotInfo['imageID'] == None or snapshotInfo['userName'] == None  :
        return False
    addSnapshotThread = p_add_snapshot_thread(snapshotInfo)
    addSnapshotThread.start()
    return True
    
def p_delete_snapshot(userName, imageID, snapshotID):
    logger.info('p_delete_snapshot')
    if userName == None or imageID == None or snapshotID == None  :
        return False
    deleteSnapshotThread = p_delete_snapshot_thread(userName, imageID, snapshotID)
    deleteSnapshotThread.start()
    return True
    
def p_apply_snapshot(userName, imageID, snapshotID):
    logger.info('p_applay_snapshot')
    if userName == None or imageID == None or snapshotID == None  :
        return False
    applySnapshotThread = p_apply_snapshot_thread(userName, imageID, snapshotID)
    applySnapshotThread.start()
    return True   '''
 
def p_add_snapshot_job(snapshotInfo):
    ret = False
    imageID = snapshotInfo.imageID
    userName = snapshotInfo.userName
    if(imageID == None or userName == None):
        return False
    ldap_ip = utility.get_ldap_server()
    snapshotInfo.id = OpenLdap.p_get_available_snapshot_id(ldap_ip,userName,imageID)
    logger.info('p_add_snapshot_job(%s)' % snapshotInfo)
    snapshotTag='TAG'+str(snapshotInfo.id)
    instanceID = (imageID[4:len(imageID)] + userName)[0:15]
    instancefile = p_getInstanceFile(userName, instanceID)
    if os.path.exists(instancefile):
        cmd_line = 'qemu-img snapshot -c SNAPSHOTTAG INSTANCEFILE'
        cmd_line = cmd_line.replace('SNAPSHOTTAG', snapshotTag)
        cmd_line = cmd_line.replace('INSTANCEFILE', instancefile)

        logger.info('p_add_snapshot_job : ' + cmd_line)
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        logger.info('p_add_snapshot_job cmd_output %s' % str(cmd_output))
        if cmd_status == 0:
            snapshotInfo.snapshotDate=p_getCurrentTimeInSeconds();
            logger.info('p_add_snapshot_job(%s)' % snapshotInfo)
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_add_snapshot_to_ldap(ldap_ip,snapshotInfo) 
    return ret   

def p_delete_snapshot_job(userName, imageID, snapshotID):
    ret = False
    logger.info('p_delete_snapshot_job(%s)' % userName+' '+imageID+' '+str(snapshotID))
    if(imageID == None or userName == None or snapshotID == None):
        return False
    snapshotTag='TAG'+str(snapshotID)
    instanceID = (imageID[4:len(imageID)] + userName)[0:15]
    instancefile = p_getInstanceFile(userName, instanceID)
    if os.path.exists(instancefile):
        cmd_line = 'qemu-img snapshot -d SNAPSHOTTAG INSTANCEFILE'
        cmd_line = cmd_line.replace('SNAPSHOTTAG', snapshotTag)
        cmd_line = cmd_line.replace('INSTANCEFILE', instancefile)

        logger.info('p_delete_snapshot_job : ' + cmd_line)
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        logger.info('p_delete_snapshot_job cmd_output %s' % str(cmd_output))
        #if cmd_status == 0:
        ldap_ip = utility.get_ldap_server()
        ret = OpenLdap.p_delete_snapshot_to_ldap(ldap_ip,userName, imageID, snapshotID)   
    return ret           
            
def p_apply_snapshot_job(userName, imageID, snapshotID):
    ret = False
    logger.info('p_apply_snapshot_job(%s)' % userName+' '+imageID+' '+str(snapshotID))
    if(imageID == None or userName == None or snapshotID == None):
        return False
    snapshotTag='TAG'+str(snapshotID)
    instanceID = (imageID[4:len(imageID)] + userName)[0:15]
    instancefile = p_getInstanceFile(userName, instanceID)
    if os.path.exists(instancefile):
        cmd_line = 'qemu-img snapshot -a SNAPSHOTTAG INSTANCEFILE'
        cmd_line = cmd_line.replace('SNAPSHOTTAG', snapshotTag)
        cmd_line = cmd_line.replace('INSTANCEFILE', instancefile)

        logger.info('p_apply_snapshot_job : ' + cmd_line)
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        logger.info('p_apply_snapshot_job cmd_output %s' % str(cmd_output))
        if cmd_status == 0:
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_set_current_snapshot_id_to_ldap(ldap_ip,userName, imageID, snapshotID)   
    return ret
    
'''class p_add_snapshot_thread(threading.Thread):
    def __init__(self,snapshotInfo):
        threading.Thread.__init__(self)
        self.snapshotInfo = snapshotInfo

    def run(self):   
        p_add_snapshot_job(self.snapshotInfo)

class p_delete_snapshot_thread(threading.Thread):
    def __init__(self,userName, imageID,snapshotID):
        threading.Thread.__init__(self)
        self.userName = userName
        self.imageID = imageID
        self.snapshotID = snapshotID

    def run(self):   
        p_delete_snapshot_job(self.userName,self.imageID,self.snapshotID)
        
class p_apply_snapshot_thread(threading.Thread):
    def __init__(self,userName, imageID,snapshotID):
        threading.Thread.__init__(self)
        self.userName = userName
        self.imageID = imageID
        self.snapshotID = snapshotID

    def run(self):   
        p_apply_snapshot_job(self.userName,self.imageID,self.snapshotID)'''

class p_transmit_transaction_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(INSTANCE_REPORT_INTV)
            if g_cc_ip!=None and g_nc_ip!=None:
                nodeIP = g_nc_ip
                ccIp=g_cc_ip
                transactions = p_euca_get_run_instance_transactions('admin')
                logger.debug('transactions: %s' %str(transactions))
                OpenLdap.transmit_instance_transaction_list(ccIp,nodeIP,transactions)
            else:
                logger.error('p_transmit_transaction_thread nodeInfo error!')
                          
 
class nodeApiHandler:
    def luhya_res_isImageDownloading(self, imageID, imgLen):
        logger.info('handle luhya_res_isImageExisit imageID = %s imageSize = %d' % (imageID, imageLen))
        ncInsCachePath = p_getImageMakingCachePath(imageID)
        isExist = p_isImageExist(ncInsCachePath, imgLen)
        return isExist

    def luhya_res_runInstanceByBaseImage(self, transactionID):
        logger.info('handle luhya_res_runInstanceByBaseImage %s' % (transactionID))
        return p_runInstanceByBaseImage(transactionID)

    def luhya_res_stopProduceImage(self, transactionID):
        logger.info('handle luhya_res_stopProduceImage %s' % (transactionID))
        return p_stopInstancebyBaseImage(transactionID)

    def luhya_res_submitImage(self, transactionID):
        logger.info('handle luhya_res_submitImage %s' % (transactionID))
        return p_submitImage(transactionID)

    def luhya_res_setNewImageInfo(self, transactionID, newImageInfo):
        logger.info('handle luhya_res_setNewImageInfo %s' % (transactionID))
        return p_setNewImageInfo(transactionID, newImageInfo)

    def luhya_res_createMakeImageTransaction(self, imageID, imageLen, user):
        logger.info('handle luhya_res_createMakeImageTransaction user = %s BaseImageID = %s BaseImagesize = %d' % (
        user, imageID, imageLen))
        id = p_CreateMakeImageTransaction(imageID, imageLen, user)
        return id

    def luhya_res_create_image_transaction(self, transaction):
        logger.info(' luhya_res_create_image_transaction : %s' % str(transaction))
        ldap_ip = utility.get_ldap_server()
        if(transaction.user==None or transaction.imageID==None):
            return None
        if(transaction.createMode == 'ISO'):
            if not OpenLdap.is_feature_can_use(ldap_ip,FEATURE_IMAGE_BY_ISO):
                return None
        if(transaction.createMode == 'P2V'):
            if not OpenLdap.is_feature_can_use(ldap_ip,FEATURE_IMAGE_BY_P2V):
                return None
        id = p_create_image_transaction(transaction)
        return id

    def luhya_res_deleteMakeImageTransaction(self, transactionID):
        logger.info('handle luhya_res_deleteMakeImageTransaction:(%s)' % (transactionID))
        return p_deleteMakeImageTransaction(transactionID)

    def luhya_res_getTransactionStatusById(self, transactionID):
        logger.info('handle luhya_res_getTransactionStatusById:(%s)' % (transactionID))
        info = None
        info = p_getTransactionStatusById(transactionID)
        return info

    def luhya_res_getAllTransaction(self):
        logger.info('handle luhya_res_getAllTransaction')
        info_list = []
        info_list = p_getAllTransaction()
        return info_list

    def euca_res_create_run_instance_transaction(self, clientData):
        transactionID = p_euca_get_transaction_id(clientData)
        if(transactionID != None):
            p_euca_update_transaction_state(thd_TRANSACT_STATE.INIT, transactionID)
        else:
            transactionID = p_create_run_instance_transaction(clientData)
        logger.info('euca_res_create_run_instance_transaction %s: ' % transactionID)
        return transactionID

    def euca_res_get_transaction_by_id(self, transactionID):
        return p_get_run_instance_transaction_byid(transactionID)

    def euca_res_delete_run_instance_transaction(self, transactionID):
        logger.info('delete_run_instance_transaction: %s ' %transactionID)
        transaction = p_euca_get_transaction(transactionID)
        if(transaction != None):
            p_euca_stop_instance(transactionID)
            switch.acquire()
            del euca_transactions[transactionID]
            switch.release()
        return True

    def euca_res_runInstance( self, transactionID ):
        logger.info('euca_res_runInstance %s: ' % transactionID)
        return p_euca_run_instance(transactionID)

    def euca_get_run_instance_transaction_list(self, userName):
        eucaTranList = p_euca_get_run_instance_transactions(userName)
        return eucaTranList

    def luhya_res_set_instance_boot_from(self, transactionID, bootFrom):
        return p_set_instance_boot_from(transactionID, bootFrom)
  
    def luhya_res_backup_instance(self, userName, imageID):
        logger.info('luhya_res_backup_instance %s: ' % imageID)
        return p_backup_instance(userName, imageID)

    def luhya_res_stop_backup_instance(self ,userName, imageID):
        logger.info('luhya_res_stop_backup_instance %s: ' % imageID)
        return p_stop_backup_instance(userName, imageID)

    def luhya_res_get_backup_time(self, userName, imageID):
        logger.info('luhya_res_get_backup_time %s: ' % imageID)
        return p_get_backup_time(userName, imageID)
        
    def luhya_res_restore_instance(self, userName, imageID):
        logger.info('luhya_res_restore_instance %s: ' % imageID)
        return p_restore_instance(userName, imageID)
    
    def luhya_res_nc_get_current_resource(self):     #start booth li
        hdSource = utility.utility_get_current_resource()
        g_source_switch.acquire()
        hdSource.netReceiveRate = g_server_resource['recvRate']
        hdSource.netSendRate = g_server_resource['sendRate']
        hdSource.cpuUtilization = g_server_resource['cpuUtilization']
        g_source_switch.release()
        hdSource.state = 'VM_STATUS_RIGHT'
        if hdSource.cpuUtilization > VM_CPU_UTILIZATION:
            hdSource.state = 'VM_STATUS_WARN'
        logger.info('state:%s,cpuUtilization:%d'% (hdSource.state,hdSource.cpuUtilization))        
        return hdSource                                      #end booth li
    

    def luhya_res_nc_attach_iso(self,isoFile , transactionID):
        logger.info('luhya_res_nc_attach_iso %s: ' % isoFile)
        return p_attach_iso(isoFile , transactionID)

    def luhya_res_nc_is_service_start(self,):
        return p_is_service_start()

    def luhya_res_nc_start_service(self,):
        return p_start_service()

    def luhya_res_nc_stop_service(self,):
        return p_stop_service()

    def luhya_res_nc_live_migrage_domains(self,migrageLists):
        logger.info('luhya_res_nc_live_migrage_domains %s: ' % migrageLists)
        return p_live_migrage_domains(migrageLists)
        
    def luhya_res_nc_add_migrage_transaction(self,transaction):
        logger.info('luhya_res_nc_add_migrage_transaction %s: ' % transaction)
        return p_add_migrage_transaction(transaction)  
        
    def luhya_res_nc_auto_migrate_receive_vms(self,migratevmLists):  
        logger.info('luhya_res_nc_update_live_vm_list')
        return p_auto_migrate_receive_vms(migratevmLists)
    
    def luhya_res_nc_is_live(self,):  
        return True
        
    def luhya_res_nc_instance_is_running(self,instanceID):  
        logger.info('luhya_res_nc_instance_is_running')
        return p_instance_is_running(instanceID)
                  
    def luhya_res_nc_get_transId_by_user_image(self,user,imageId):
        return p_get_transId_by_user_image(user,imageId)
    
    def luhya_res_nc_reboot_instance(self,instanceID):
        return p_rebootInstance(instanceID)   

    def luhya_res_add_snapshot(self ,snapshotInfo):
        logger.info('luhya_res_add_snapshot  ' )
        return p_add_snapshot_job(snapshotInfo)

    def luhya_res_delete_snapshot(self ,userName, imageID, snapshotID):
        logger.info('luhya_res_delete_snapshot ' )
        return p_delete_snapshot_job(userName, imageID, snapshotID)
        
    def luhya_res_apply_snapshot(self ,userName, imageID,snapshotID):
        logger.info('luhya_res_applay_snapshot ' )
        return p_apply_snapshot_job(userName, imageID,snapshotID)   

    def luhya_res_start_vm(self, clientData):
        logger.info('luhya_res_start_vm :%s' %str(clientData))
        transactionID = p_euca_get_transaction_id(clientData)
        if(transactionID != None):
            switch.acquire()
            euca_transactions[transactionID]['clientData'] = clientData
            switch.release()
            p_euca_update_transaction_state(thd_TRANSACT_STATE.INIT, transactionID)
        else:
            transactionID = p_create_run_instance_transaction(clientData)
        return p_euca_run_instance(transactionID)

    def luhya_res_stop_vm(self,clientData):
        tran_id = p_get_transId_by_user_image(clientData.user,clientData.image_id)
        if(tran_id != None):
            p_euca_stop_instance(tran_id)
            switch.acquire()
            del euca_transactions[tran_id]
            switch.release()       
        return True

    def luhya_res_stop_instance(self,user,image_id):
        tran_id = p_get_transId_by_user_image(user,image_id)
        if(tran_id != None):
            p_euca_stop_instance(tran_id)
            switch.acquire()
            del euca_transactions[tran_id]
            switch.release()       
        return True    
    
    def luhya_res_get_instance_states(self, userName):
        ins = []
        eucaTranList = p_euca_get_run_instance_transactions(userName)
        for eucaTran in eucaTranList:
            instance = thd_instance_info()
            instance.instance_id = eucaTran.instanceID
            instance.image_id = eucaTran.imageID
            instance.user = eucaTran.user
            instance.state = eucaTran.state
            instance.n_port = eucaTran.instancePort
            instance.str_password = eucaTran.instancePassword
            ins.append(instance)
        return ins

# g_NcThriftServer_main_interface,NcThriftServer main interface, starting point 
class g_NcThriftServer_main_interface(threading.Thread):
    "g_NcThriftServer_main_interface"

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            logger.info('g_NcThriftServer_main_interface running ...')
            hostIp = utility.get_local_publicip()
            logger.debug('local ip is %s' %hostIp)
            ldap_ip = utility.get_ldap_server()
            if ldap_ip!=None:
                logger.debug('ldapip is %s' %ldap_ip)
                ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_NC,hostIp)
                if ret:
                    p_init_backup_tran()
                    handler = nodeApiHandler()
                    processor = nodeApi.Processor(handler)
              
                    transport = TSocket.TServerSocket(hostIp, thd_port.THRIFT_NC_PORT)
                    tfactory = TTransport.TBufferedTransportFactory()
                    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
                    #server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
                    #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
                    server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)
                    logger.info('Starting the NcThriftServer ...')

                    server.serve()
                    logger.error('NcThriftServer stopped.')
                    break
                else:
                    time.sleep(2)
            else:
                time.sleep(2)

# NcThriftServerexternal interface
def preInit (user_data):
    logger.info('pre_init starting ...')
    
    ip_intv_thread = p_get_global_ip_intv_thread()
    ip_intv_thread.start() 
    
    regnc_thread = p_register_node_thread()
    regnc_thread.start()   
    
    NcThriftServer_main = g_NcThriftServer_main_interface()
    NcThriftServer_main.start()
    getSourceThread = p_get_server_source_thread()
    getSourceThread.start()
    
    transactionThread = p_transmit_transaction_thread()
    transactionThread.start() 
    
    ncresource = p_transmit_server_source_thread()
    ncresource.start()
    
    heartBeat_thread = p_heart_beat_thread()
    heartBeat_thread.start()
           
    log_string = 'started g_NcThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string)

    p_start_migrate_monitor()
    
    return 0

def postInit (user_data):
    pass
