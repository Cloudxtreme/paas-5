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
import logging
import time
import os
sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.interface import clusterApi
from cloudbot.interface.ttypes import *  
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

from cloudbot.utils import OpenLdap,utility
import threading
from cloudbot.utils.const_def import *

g_server_resource = {'recvRate':0,'sendRate':0,'cpuUtilization':0}
g_source_switch = threading.Lock()
logger = utility.init_log()
g_cc_transaction = {}
g_transaction_switch= threading.Lock()

g_clc_ip = None
g_cc_ip = None
g_nc_source = {}
g_nc_heart_beat = {}


def p_get_cc_name_conf():
    ccName = None
    fh = os.popen('cat ' + CC_CONF_FILE)
    for ln in fh.readlines():    
        if 'CC_NAME' in ln:
            ls = ln.rsplit('"')
            ccName = ls[1]
    return ccName

def p_register_cluster():
    hostIp = utility.get_local_publicip()
    while True:
        ldap_ip = utility.get_ldap_server()
        # avoid the ip address cant be read
        if ldap_ip!=None:
            clusterInfo = OpenLdap.p_get_clusterInfo_by_ccIp(ldap_ip,hostIp)
            if clusterInfo!=None:
                if clusterInfo.clusterName==None :
                    ccName = p_get_cc_name_conf()
                    if ccName!=None:
                        OpenLdap.p_register_cluster(ldap_ip,ccName,hostIp)
                    else:
                        break
                else:
                    break
        time.sleep(DEFAULT_DELAY)
    
    
class p_register_cluster_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        p_register_cluster()


def p_heart_beat_timer():
    global g_clc_ip
    global g_cc_ip
    if g_clc_ip!=None and g_cc_ip!=None:
        OpenLdap.p_all_heart_beat(g_clc_ip,g_cc_ip,'cluster')
    heart = threading.Timer(HEART_BEAT_INTV , p_heart_beat_timer)
    heart.start()

def p_nc_heart_beat(ncIp):
    global g_nc_heart_beat
    ret = True
    if not g_nc_heart_beat.has_key(ncIp):
        ldap_ip = utility.get_ldap_server()
        re = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_NC,ncIp)
        if re:
            g_nc_heart_beat[ncIp] = time.time()
        else:
            ret = False
    else:
        g_nc_heart_beat[ncIp] = time.time()
    return ret

def p_nc_heart_beat_isAlive():
    logger.debug('p_nc_heart_beat_isAlive()')
    global g_nc_heart_beat
    heartT = time.time()
    for ip in g_nc_heart_beat:
        if (heartT - g_nc_heart_beat[ip]) < 4:
            logger.debug('NC %s is alive' % ip)
        else:
            logger.debug('NC %s is dead!!!' % ip)
            if g_clc_ip!=None:
                OpenLdap.luhya_nc_dead(g_clc_ip,ip,thd_SERVICE_TYPE.CLOUD_NC)
    heart = threading.Timer(4.0,p_nc_heart_beat_isAlive)
    heart.start()

def p_cc_hard_source(ncIp,hdSource):
    logger.info('p_cc_hard_source node IP:%s',ncIp)
    global g_nc_source
    ret = False
    if ncIp != None:
        g_nc_source[ncIp] = hdSource
        ret = True
    return ret

def p_dispatch_nodes():
    nodeIp = None
    ldap_ip = utility.get_ldap_server()
    clusterInfo = OpenLdap.p_get_clusterInfo_by_ccIp(ldap_ip,g_cc_ip)
    if clusterInfo!=None:
        nodes = OpenLdap.p_get_nodeInfo_by_clusterName(ldap_ip,clusterInfo.clusterName)
        if nodes!=None and len(nodes)>0:
            nodeIp = nodes[0].hostIp
    return nodeIp


def p_start_vm(clientInfo):
    nodeIp = None
    ret = 0
    if clientInfo.is_assign_node!=None and clientInfo.is_assign_node:
        nodeIp = clientInfo.node_ip
    else:
        nodeIp = p_dispatch_nodes()
    if nodeIp!=None:
        logger.debug('p_start_vm node:%s' %nodeIp)
        ret = OpenLdap.p_nc_start_vm(nodeIp,clientInfo)
    else:
        ret = -7
    retInfo = thd_run_instance_ret()
    retInfo.node_ip = nodeIp
    retInfo.return_value = ret
    logger.debug('p_start_vm the return value:%s' %str(retInfo))
    return retInfo
        

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

class p_transmit_transcationlist_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(INSTANCE_REPORT_INTV)
            logger.debug('p_transmit_transcationlist_thread:%s' %str(g_cc_transaction))
            for nodeIp in g_cc_transaction.keys() :
                g_transaction_switch.acquire()
                transactions = g_cc_transaction[nodeIp][:]
                g_transaction_switch.release()
                logger.debug('p_transmit_transcationlist_thread transaction : %s' %str(transactions))
                if g_clc_ip != None:
                    transmitData = thd_transmit_data()
                    transmitData.node_ip = nodeIp
                    transmitData.transactions = transactions
                    logger.debug('p_transmit_transcationlist_thread transmitData:%s: ' %str(transmitData))
                    OpenLdap.p_set_transmit_transactionlist(g_clc_ip,transmitData)


def p_get_transaction_list(nodeIP,transAllList):
    g_cc_transaction[nodeIP] = transAllList
    logger.debug(g_cc_transaction)
    return True


class p_heart_beat_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_CC,utility.get_local_publicip())
            if ret: 
                p_nc_heart_beat_isAlive()
                p_heart_beat_timer()
                break
            else:
                time.sleep(DEFAULT_DELAY)

class p_get_nodeInfo_byClusterName_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        logger.debug('p_get_nodeInfo_byClusterName_thread start ....')
        global g_nc_heart_beat
        while True:
            ldap_ip = utility.get_ldap_server()
            ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_CC,utility.get_local_publicip())
            if ret:
                clusterInfo = OpenLdap.p_get_clusterInfo_by_ccIp(ldap_ip,g_cc_ip)
                if clusterInfo != None:
                    nodeList = OpenLdap.p_get_nodeInfo_by_clusterName(ldap_ip,clusterInfo.clusterName)
                    if nodeList != None:
                        for nodeInfo in nodeList:
                            g_nc_heart_beat[nodeInfo.hostIp] = time.time()
                        break
            time.sleep(HEART_BEAT_INTV)
            logger.debug('waiting in p_get_nodeInfo_byClusterName_thread()!!!')
        

class p_transmit_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.debug('p_transmit_server_source_thread...')
        global g_nc_source
        global g_cc_ip
        global g_clc_ip
        while True:                        
            hdSource = utility.utility_get_current_resource()
            g_source_switch.acquire()
            hdSource.net_receiverate = g_server_resource['recvRate']
            hdSource.net_sendrate = g_server_resource['sendRate']
            hdSource.cpu_utilization = g_server_resource['cpuUtilization']
            g_source_switch.release()
            hdSource.state = 'HW_STATUS_OK'
            if hdSource.cpu_utilization > VM_CPU_UTILIZATION:
                hdSource.state = 'HW_STATUS_WARN'
            if g_cc_ip!=None:    
                g_nc_source[g_cc_ip] = hdSource
            logger.info(g_nc_source)
            nc_source = g_nc_source.copy()
            for ip in nc_source:
                if g_clc_ip!=None:
                    OpenLdap.p_transmit_hard_source(g_clc_ip,ip,nc_source[ip])
            time.sleep(SERVER_SOURCE_INTV)

class p_get_ip_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):    
        while True:
            logger.debug('p_get_ip_thread...start')
            global g_clc_ip
            global g_cc_ip
            
            g_cc_ip = utility.get_local_publicip()
            ldap_ip = utility.get_ldap_server()
            # avoid the ip address cant be read
            if ldap_ip!=None:
                ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_CC,g_cc_ip)
                if ret:
                    ldap_ip =  utility.get_ldap_server()   
                    g_clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                if (g_clc_ip != None)  and (g_cc_ip != None):
                    logger.info('g_cc_ip:%s,g_clc_ip:%s' %(g_cc_ip,g_clc_ip))               
                    break
                else:
                    logger.debug('waiting in p_get_ip_thread()!!!')
            time.sleep(DEFAULT_DELAY)

def p_regnc_set_cc_global(ncIp):
    if ncIp!=None:
        g_nc_heart_beat[ncIp] = time.time()
        g_nc_source[ncIp] = None
    return True


def p_is_service_start():
	serviceName = CLOUD_CC
	return utility.p_is_service_start(serviceName)

def p_start_service():
    serviceName = CLOUD_CC
    return utility.p_start_service(serviceName)	 

def p_stop_service():
    serviceName = CLOUD_CC
    return utility.p_stop_service(serviceName)

class clusterApiHandler:
    def luhya_res_getInstanceByNode(self, nodeIp):
        ins = []
        return ins
    
    def luhya_res_is_service_start(self,):
	return p_is_service_start()        

    def luhya_res_start_service(self,):
        return p_start_service()
    
    def luhya_res_stop_service(self,):
        return p_stop_service()

    def luhya_res_get_node_hw_resource(self,ncIp,hdSource):
        return p_cc_hard_source(ncIp,hdSource)
        
    def luhya_res_nc_heart_beat(self,ncIp):
        ret = False
        if ncIp != None:
            ret = p_nc_heart_beat(ncIp)
        return ret    
        
    def luhya_res_get_current_resource(self,):
        hdSource = utility.utility_get_current_resource()
        g_source_switch.acquire()
        hdSource.net_receiverate = g_server_resource['recvRate']
        hdSource.net_sendrate = g_server_resource['sendRate']
        hdSource.cpu_utilization = g_server_resource['cpuUtilization']
        g_source_switch.release()
        hdSource.state = 'HW_STATUS_OK'
        if hdSource.cpu_utilization > VM_CPU_UTILIZATION:
            hdSource.state = 'HW_STATUS_WARN'        
        return hdSource 

    def luhya_res_add_node(self, nodeIp):
        return utility.p_register_service('eucalyptus-nc',nodeIp,None)

    def luhya_res_remove_node(self, nodeIp):
            #TODO
            return True    
    
    def luhya_res_has_node(self, nodeIp):
    		return p_has_node(nodeIP)    
    
    def luhya_res_run_instance_transaction_list(self,nodeIP,transAllList):
#        logger.info('luhya_res_run_instance_transaction_list %s' % str(transAllList))
        return p_get_transaction_list(nodeIP,transAllList)
    
    def luhya_res_init_nc_global_info(self,ncIp):
        return p_regnc_set_cc_global(ncIp)
    
    def luhya_res_start_vm(self, clientInfo):        
        return p_start_vm(clientInfo)
        
            
class g_ClusterThriftServer_main_interface(threading.Thread):
    "g_LdapThriftServer_main_interface"

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while True:
            hostIp = utility.get_local_publicip()
            logger.info( 'g_ClusterThriftServer_main_interface cc register :%s ' %hostIp)
            ldap_ip = utility.get_ldap_server()
            # avoid the ip address cant be read
            if ldap_ip!=None:
                ret = OpenLdap.p_is_register(ldap_ip,thd_SERVICE_TYPE.CLOUD_CC,hostIp)
                if ret:
                    logger.info('g_ClusterThriftServer_main_interface running ...')
                    handler = clusterApiHandler()
                    processor = clusterApi.Processor(handler)
                    transport = TSocket.TServerSocket(hostIp, thd_port.THRIFT_CC_PORT)
                    tfactory = TTransport.TBufferedTransportFactory()
                    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

                    #server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
                    
                    # You could do one of these for a multithreaded server
                    #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
                    server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)

                    logger.info('Starting cluster the server...')
                    server.serve()
                    logger.error('thrift cluster server quit!')
                    break
                else:
                    time.sleep(DEFAULT_DELAY)
            else:
                time.sleep(DEFAULT_DELAY)

        
# CcThriftServerexternal interface
def preInit (user_data):
    logger.info('ClusterThriftServer_main pre_init starting ...')
    ip_thread = p_get_ip_thread()
    ip_thread.start()
    
    regcc_thread = p_register_cluster_thread()
    regcc_thread.start()
    
    ClusterThriftServer_main = g_ClusterThriftServer_main_interface()
    ClusterThriftServer_main.start()
    getSourceThread = p_get_server_source_thread()
    getSourceThread.start()
    translistThread = p_transmit_transcationlist_thread()
    translistThread.start()
    
    globalNcThread = p_get_nodeInfo_byClusterName_thread()
    globalNcThread.start()
    hdSourceThread = p_transmit_server_source_thread()
    hdSourceThread.start()    
    heartBeatThread = p_heart_beat_thread()
    heartBeatThread.start()     
      
            
    log_string = 'started g_CcThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string)

    return 0     #sys.exit()


def postInit (user_data):
  pass

