
import getopt, sys, os, stat
import socket
import fcntl
import struct
import logging
import logging.handlers
import commands

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from cloudbot.interface import ldapApi
from cloudbot.interface import nodeApi
from cloudbot.interface import walrusApi
from cloudbot.interface import clcApi
from cloudbot.interface import clusterApi
from cloudbot.interface.ttypes import * 
from cloudbot.utils.const_def import *

#===============================
#   LDAP Thrift Interfaces
#===============================

def get_clc_ip(ldap_ip):
    clcIP = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport.setTimeout(THRIFT_TIMEOUT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clcIP = client.luhya_reg_getClcIp()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_clc_ip:%s' % (tx.message))
    return clcIP

def get_certificate_Code(ldap_ip,userId):
    certificateCode = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        certificateCode = client.luhya_reg_getCertificateCode(userId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_certificate_Code:%s' % (tx.message))
    return certificateCode
 
def get_walrus_info(ldap_ip):
    hostip = None
    port = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        hostip = client.luhya_reg_getWalrusIp()
        port = client.luhya_reg_getWalrusPort()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_walrus_info:%s' % (tx.message))
    return hostip,port

def get_image_info(ldap_ip,imageID):
	image_info = thd_ImageInfo()
	try:
		transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		image_info = client.luhya_reg_getImageInfo(imageID)
		transport.close()
	except Thrift.TException, tx:
		logging.warn('get_image_info:%s' % (tx.message))
	return image_info

def get_image_location(ldap_ip,imageID):
    location = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        imageInfo = client.luhya_reg_getImageInfo(imageID)
        if(imageInfo!=None):
            location = imageInfo.imageLocation
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_image_location:%s' % (tx.message))
    return location

def get_image_platform(ldap_ip,imageID):
    platform = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        imageInfo = client.luhya_reg_getImageInfo(imageID)
        if(imageInfo!=None):
            platform = imageInfo.platform
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'get_image_platform:%s' % (tx.message))
    return platform


def update_image_toldap(ldap_ip,imageInfo):
    if(imageInfo==None or imageInfo.imageId==None):
        logging.warn('update_image_toldap:the image info is error!')
        return False
    res = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        res = client.luhya_reg_updateImageInfo(imageInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('update_image_toldap:%s' % (tx.message))
    return res

def p_add_image_info(ldap_ip,imageInfo):
    if(imageInfo==None or imageInfo.imageId==None):
        logging.warn('p_add_image_info:the image info is error!')
        return False
    res = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        res = client.luhya_reg_addImageInfo(imageInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_add_image_info error:%s' % (tx.message))
    return res    

def get_category_list(ldap_ip):
    cal = []
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        cal = client.luhya_reg_getCategoryList()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'get_category_list error:%s' % (tx.message))
    return cal
	
def get_make_image_resource(ldap_ip):
    res=2
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        res = client.luhya_reg_getMakeImageResource()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'get_make_image_resource error:%s' % (tx.message))
    return res

def is_feature_can_use(ldap_ip,featureId):
    return True
    res = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        res = client.luhya_reg_get_feature_status(featureId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'is_feature_can_use error:%s' % (tx.message))
    return res

def get_all_vmConfigs(ldap_ip):
    vmConfigs = None	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        vmConfigs = client.euca_reg_get_all_vmconfig()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'get_all_vmConfigs error:%s' % (tx.message))
    return vmConfigs

def get_vmConfig_by_id(ldap_ip,vmconfigId):
    vmConfig = thd_vmConfig()	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        vmConfig = client.euca_reg_get_vmconfig_by_id(vmconfigId)
        transport.close()
    except Thrift.TException, tx:
	    logging.warn('get_vmConfig_by_id error:%s' %tx.message)
    return vmConfig


def get_all_images(ldap_ip):
    images = None	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        images = client.luhya_reg_getImageList()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_all_images error:%s' %tx.message)
    return images	

def get_client_users(ldap_ip):
    users = None	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        users = client.luhya_reg_get_client_user()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_client_users error:%s' %tx.message)
    return users   

def p_get_nodeinfo_by_ip(ldap_ip,nodeIp):
     nodeInfo = None	
     try:
         transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
         transport = TTransport.TBufferedTransport(transport)
         protocol = TBinaryProtocol.TBinaryProtocol(transport)
         client = ldapApi.Client(protocol)
         transport.open()
         nodeInfo = client.luhya_reg_get_nodeinfo_by_nodeIp(nodeIp)
         transport.close()
     except Thrift.TException, tx:
         logging.warn('p_get_nodeinfo_by_ip error:%s' %tx.message)
     return nodeInfo  
	
def get_vmConfigs_by_user(ldap_ip,userName):
    vmConfigs = []	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        vmConfigs = client.euca_reg_get_vmconfigs_by_user(userName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_vmConfigs_by_user error:%s' %tx.message)
    return vmConfigs	

def p_get_migrate_info_list(ldap_ip):
    lists = []
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        lists = client.luhya_reg_get_migrate_Info_list('admin')
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_migrate_info_list error:%s' %tx.message)
    return lists 

def p_get_live_migrate_node_list(ldap_ip):
    lists = []	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        lists = client.luhya_reg_get_node_migrate_list()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_live_migrate_node_list error:%s' %tx.message)
    return lists
		  
def get_node_list(ldap_ip):
    nodes = []	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        nodes = client.luhya_reg_getNodeList()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_node_list error:%s' %tx.message)
    return nodes
	
def p_get_available_snapshot_id(ldap_ip,userName,imageID):
    snapshot_id = 1	
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        snapshot_id = client.luhya_reg_get_available_snapshot_id(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_available_snapshot_id error:%s' %tx.message)
    return snapshot_id	

def p_add_snapshot_to_ldap(ldap_ip,snapshotInfo):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_add_snapshot(snapshotInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_add_snapshot_to_ldap error:%s' %tx.message)
    return ret	

def p_delete_snapshot_to_ldap(ldap_ip,userName, imageID, snapshotID):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_delete_snapshot(userName, imageID, snapshotID)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_delete_snapshot_to_ldap error:%s' %tx.message)
    return ret	

def p_set_current_snapshot_id_to_ldap(ldap_ip,userName,imageID,snapshotID):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_set_current_snapshot_id(userName,imageID,snapshotID)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_set_current_snapshot_id_to_ldap error:%s' %tx.message)
    return ret	
		
def p_is_admin(ldap_ip,userName):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_is_admin(userName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_is_admin error:%s' %tx.message)
    return ret	

def p_get_image_bucket(ldap_ip):
    bucket = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        bucket = client.luhya_reg_getWalrusBucketPath()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_image_bucket error:%s' % (tx.message))
    return bucket    

def p_get_image_xml(ldap_ip,imageId):
    xml = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        xml = client.luhya_reg_getImageXml(imageId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_image_xml error:%s' % (tx.message))
    return xml    

def p_get_cluster_ip(ldap_ip,clusterName):
    clusterIp = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clusterInfo = client.luhya_reg_get_clusterinfo_by_cluster(clusterName)
        clusterIp = clusterInfo.hostIp
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_cluster_ip error:%s' % (tx.message))
    return clusterIp     
        
    
def p_set_make_image_node(ldap_ip,nodeIp):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_set_make_image_node(nodeIp)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_set_make_image_node error:%s' % (tx.message))
    return ret

def p_get_make_image_node(ldap_ip):
    nodeIp = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        nodeIp = client.luhya_reg_getMakeImageNode()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_set_make_image_node error:%s' % (tx.message))
    return nodeIp

def get_cluster_list(ldap_ip):
    clusters=[]
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clusters = client.luhya_reg_getClusterList()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_cluster_list error:%s' %tx.message)
    return clusters  
  
def get_clusterinfo_by_cluster(ldap_ip,clusterName):
    clusterInfo = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clusterInfo = client.luhya_reg_get_clusterinfo_by_cluster(clusterName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_clusterinfo_by_cluster error:%s' %tx.message)
    return clusterInfo
    
def p_get_services_by_ip(ldap_ip,ip):
    services = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        services = client.luhya_reg_get_services_by_ip(ip)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_services_by_ip error:%s' %tx.message)
    return services	

def p_get_all_service_ip(ldap_ip):
    ipList=[]
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ipList = client.luhya_reg_get_all_service_ip()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_all_service_ip error:%s' %tx.message)
    return ipList

def get_all_domains(ldap_ip):
    domainList=[]
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        domainList = client.luhya_reg_get_all_domains()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_all_domains error:%s' %tx.message)
    return domainList


def get_max_private_instances(ldap_ip,user):
    ret = 1
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_get_max_private_instances(user)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_max_private_instances error:%s' %tx.message)
    return ret


def p_get_nodeInfo_by_clusterName(ldap_ip,clusterName):
    nodeList = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        nodeList = client.luhya_reg_getNodeInfoByCluster(clusterName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_nodeInfo_by_clusterName error:%s' %tx.message)
    return nodeList

def p_get_clusterInfo_by_ccIp(ldap_ip,ccIp):
    clusterInfo = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clusterInfo = client.luhya_reg_get_clusterInfo_by_ccIp(ccIp)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_clusterInfo_by_ccIp:%s' % (tx.message))
    return clusterInfo

def luhya_get_clusterList(ldap_ip):
    listInfo = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        listInfo = client.luhya_reg_getClusterList()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'luhya_get_clusterList error:%s' % (tx.message))
    return listInfo    

def p_init_clc_info(ldap_ip,clcIp):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_init_clc_info(clcIp)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_init_clc_info error: %s' % (tx.message))    
    return ret

def p_init_walrus_info(ldap_ip,walrusIp):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_init_walrus_info(walrusIp)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_init_walrus_info error: %s' % (tx.message))    
    return ret    

def p_register_cluster(ldap_ip,ccName,hostIp):
    ret = False
    if ccName==None or hostIp==None:
        return ret
    clusterInfo = thd_ClusterInfo()
    clusterInfo.clusterName = ccName
    clusterInfo.hostIp = hostIp
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_init_cluster_info(clusterInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'register_cluster error: %s' % (tx.message))  
    return ret

def p_register_node(ldap_ip,nodeInfo):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_init_node_info(nodeInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_register_node error: %s' % (tx.message))   
    return ret


def p_add_user(ldap_ip,userInfo):
    ret = False
    if userInfo.userName==None or userInfo.bCryptedPassword==None:
        return False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_add_user(userInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_add_user error: %s' % (tx.message))   
    return ret

def p_get_ins_report_intv(ldap_ip):
    ret = None
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_get_ins_report_intv()
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_ins_report_intv error: %s' % (tx.message))   
    return ret

def p_is_register(ldap_ip,servID,hostIp):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_is_registered(servID,hostIp)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_is_registered error: %s' % (tx.message))   
    return ret

def p_get_images_by_user(ldap_ip,user):
    ret = []
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.euca_reg_getImageList(user)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_images_by_user error: %s' % (tx.message))   
    return ret

def p_ldap_online(ldap_ip):
    ret = False
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport.setTimeout(THRIFT_TIMEOUT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_is_online()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_ldap_online:%s' % (tx.message))
    return ret 

def p_user_logon(ldap_ip,userName,password,domain):
    ret = -1
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.euca_reg_domain_user_logon( userName, password, domain)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_is_online:%s' % (tx.message))
    return ret    

def get_user_info(ldap_ip,userName):
    ret = thd_UserInfo()
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.euca_reg_domain_user_logon( userName, password, domain)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_is_online:%s' % (tx.message))
    return ret

#===============================
#   CLC Thrift Interfaces
#===============================
def get_client_data(clc_ip,user,request_ip):
    client_infos = []
    try:
        transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
        transport.setTimeout(THRIFT_TIMEOUT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = clcApi.Client(protocol)
        transport.open()
        client_infos = client.luhya_clc_get_client_data(user,request_ip)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_client_data error:%s' %tx.message)
    return client_infos


def p_set_migrage_state(clc_ip, transactionID,state):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_migrage_state(transactionID,state)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_migrage_state error:%s' %tx.message)
    return ret   

def p_set_backup_state(clc_ip, user_name, image_id, state):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_backup_state(user_name, image_id, state)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_backup_state error:%s' %tx.message)
    return ret 

def p_set_backup_progress(clc_ip, user_name, image_id, progress):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_backup_progress(user_name, image_id, progress)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_backup_progress error:%s' %tx.message)
            ret = False
	return ret 

def p_set_restore_progress(clc_ip, user_name, image_id, progress):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_restore_progress(user_name, image_id, progress)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_restore_progress error:%s' %tx.message)
            ret = False
	return ret

def p_set_restore_state(clc_ip, user_name, image_id, state):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_restore_state(user_name, image_id, state)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_restore_state error:%s' %tx.message)
            ret = False
	return ret

def p_set_transmit_transactionlist(clc_ip,transmitData):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_transmit_transcation(transmitData)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_set_transmit_transactionlist error:%s'%tx.message)
    return ret  

def p_transmit_hard_source(clc_ip,IP,hdSource):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_transmit_source(IP,hdSource)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_transmit_hard_source error:%s' %tx.message)
    return ret

def p_all_heart_beat(clc_ip,ip,name):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_heart_beat(ip,name)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_all_heart_beat:%s' % (tx.message))
    return ret

def luhya_nc_dead(clc_ip,node_ip,service_id):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_nc_heart_beat_dead(node_ip,service_id)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'luhya_nc_dead error:%s' % (tx.message))
    return ret

def p_add_service_resource(clc_ip,hostIp,serviceId):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_add_sevice_resource(hostIp,serviceId)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_add_service_resource error: %s' % (tx.message))
    return ret     

def p_get_resource_by_ip(clc_ip,hostIp):    
    ret = None
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_get_resource_by_ip(hostIp)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_get_resource_by_ip error: %s' % (tx.message))
    return ret    


def p_delimg_update_global(clc_ip,imageId):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_delimg_update_global(imageId)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'delimg_update_global error: %s' % (tx.message))
    return ret    

def p_delvm_update_global(clc_ip,vmConfigId):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_delvm_update_global(vmConfigId)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_delvm_update_global error: %s' % (tx.message))
    return ret

def p_updateimg_update_global(clc_ip,imageInfo):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_updateimg_update_global(imageInfo)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_updateimg_update_global error: %s' % (tx.message))
    return ret

def p_updatevm_update_global(clc_ip,vmconfig):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_updatevm_update_global(vmconfig)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_updatevm_update_global error: %s' % (tx.message))
    return ret

def p_addimg_update_global(clc_ip,imageInfo):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_addimg_update_global(imageInfo)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_addimg_update_global error: %s' % (tx.message))
    return ret

def p_addvm_update_global(clc_ip,vmconfig):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_addvm_update_global( vmconfig)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_addvm_update_global error: %s' % (tx.message))
    return ret

def clc_start_vm(clc_ip, clientInfo):
    ret = -1
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_clc_start_vm(clientInfo)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('clc_start_vm:%s' %tx.message)
    return ret        
    		
def clc_stop_vm(clc_ip, clientInfo):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_clc_stop_vm(clientInfo)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('clc_stop_vm:%s' %tx.message)
    return ret           

def p_is_vmconfig_used(clc_ip, vmconfig_id):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_is_vmconfig_used(vmconfig_id)
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_is_vmconfig_used:%s' %tx.message)
    return ret


def get_user_info(ldap_ip,userName):
    ret = thd_UserInfo()
    try:
        transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        ret = client.luhya_reg_get_user_info( userName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_user_info:%s' % (tx.message))
    return ret 

def p_get_available_snapshot_num(ldap_ip,userName,imageID):
    snapshot_num = 0
    try:
    	transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
    	transport = TTransport.TBufferedTransport(transport)
    	protocol = TBinaryProtocol.TBinaryProtocol(transport)
    	client = ldapApi.Client(protocol)
    	transport.open()
    	snapshot_num = client.luhya_reg_get_available_snapshot_num(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
    	logging.warn('p_get_available_snapshot_num:%s' % (tx.message))    
    return snapshot_num

def p_get_current_snapshot_id(ldap_ip,userName,imageID):
    snapshot_id = -1
    try:
    	transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
    	transport = TTransport.TBufferedTransport(transport)
    	protocol = TBinaryProtocol.TBinaryProtocol(transport)
    	client = ldapApi.Client(protocol)
    	transport.open()
    	snapshot_id = client.luhya_reg_get_current_snapshot_id(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
    	logging.warn('p_get_current_snapshot_id:%s' % (tx.message))    
    return snapshot_id

def p_get_snapshot_list(ldap_ip,userName,imageID):
    snapshot_list = []
    try:
    	transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
    	transport = TTransport.TBufferedTransport(transport)
    	protocol = TBinaryProtocol.TBinaryProtocol(transport)
    	client = ldapApi.Client(protocol)
    	transport.open()
    	snapshot_list = client.luhya_reg_get_snapshot_list(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
    	logging.warn('p_get_snapshot_list:%s' % (tx.message))    
    return snapshot_list

def p_get_snapshotInfo_by_id(ldap_ip,userName,imageID,snapshotID):
    snapInfo = thd_snapshot()
    try:
      transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
      transport = TTransport.TBufferedTransport(transport)
      protocol = TBinaryProtocol.TBinaryProtocol(transport)
      client = ldapApi.Client(protocol)
      transport.open()
      snapInfo = client.luhya_reg_get_snapshotInfo_by_id(userName,imageID,snapshotID)
      transport.close()
    except Thrift.TException, tx:
      logging.warn('p_get_snapshotInfo_by_id:%s' % (tx.message))    
    return snapInfo

def p_modify_snapshot(ldap_ip,snapshotInfo):
    ret = False
    try:
      transport = TSocket.TSocket(ldap_ip, thd_port.THRIFT_LDAP_PORT)
      transport = TTransport.TBufferedTransport(transport)
      protocol = TBinaryProtocol.TBinaryProtocol(transport)
      client = ldapApi.Client(protocol)
      transport.open()
      ret = client.luhya_reg_modify_snapshot(snapshotInfo)
      transport.close()
    except Thrift.TException, tx:
      logging.warn('p_modify_snapshot:%s' % (tx.message))    
    return ret
        

def p_clc_online(clc_ip):
    ret = False
    if clc_ip!=None:
        try:
            transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
            transport.setTimeout(THRIFT_TIMEOUT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_is_online()
            transport.close()
        except Thrift.TException, tx:
            logging.warn('p_clc_online:%s' % (tx.message))
    return ret

#===============================
#   Walrus Thrift Interfaces
#===============================
def get_walrus_free_disk(ldap_ip):
    space = -1
    walrusIp,port = get_walrus_info(ldap_ip)
    if(walrusIp!=None):
        try:
            transport = TSocket.TSocket(walrusIp, thd_port.THRIFT_WALRUS_PORT )
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = walrusApi.Client(protocol)
            transport.open()
            space = client.luhya_res_getFreeDisk()
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'get_walrus_free_disk error:%s' % (tx.message))
	return space

def get_walrus_file_length(ldap_ip,fileName):
	len = -1
	walrusIp,port = get_walrus_info(ldap_ip)
	if(walrusIp!=None):
		try:
			transport = TSocket.TSocket(walrusIp, thd_port.THRIFT_WALRUS_PORT )
			transport = TTransport.TBufferedTransport(transport)
			protocol = TBinaryProtocol.TBinaryProtocol(transport)
			client = walrusApi.Client(protocol)
			transport.open()
			len = client.luhya_res_get_file_length(fileName)
			transport.close()
		except Thrift.TException, tx:
			logging.warn( 'get_walrus_file_length error:%s' % (tx.message))
	return len

def p_getImageLength(ldap_ip,imageId):
    imageLen = -1
    hostIp,port = get_walrus_info(ldap_ip)
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_WALRUS_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = walrusApi.Client(protocol)
            transport.open()
            imageLen = client.luhya_res_getImageLength(imageId)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_getImageLength error:%s' % (tx.message))
    return imageLen

def p_create_walrus_dir(ldap_ip,imagePath):
    ret = False
    walrusIp,port = get_walrus_info(ldap_ip)
    if(walrusIp!=None):
        try:
            transport = TSocket.TSocket(walrusIp, thd_port.THRIFT_WALRUS_PORT )
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = walrusApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_create_dir(imagePath)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_create_walrus_dir:%s' % (tx.message))
    return ret    



#===============================
#   CC Thrift Interfaces
#===============================

# to run instance ,from cc    
def p_cc_start_vm(ccIp,clientInfo):
    ret = None
    try:
        transport = TSocket.TSocket(ccIp, thd_port.THRIFT_CC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = clusterApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_start_vm(clientInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_cc_start_vm error:%s' % (tx.message))    
    return ret    

def transmit_instance_transaction_list(ccIp,nodeIP,transAllList):
    logging.debug('transmit_instance_transaction_list %s' % str(transAllList))
    flag = False
    try:
        transport = TSocket.TSocket(ccIp, thd_port.THRIFT_CC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = clusterApi.Client(protocol)
        transport.open()
        flag = client.luhya_res_run_instance_transaction_list(nodeIP,transAllList)
        transport.close()
    except Thrift.TException, tx:
		logging.warn( 'transmit_instance_transaction_list:%s' % (tx.message))
    return flag



def p_transmit_cluster_source(ccIp,ncIp,hdSource):
    ret = False
    if ccIp != None:
        try:
            transport = TSocket.TSocket(ccIp, thd_port.THRIFT_CC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clusterApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_get_node_hw_resource(ncIp,hdSource)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_transmit_cluster_source error:%s' % (tx.message))
    return ret            
            

def p_nc_heart_beat(ccIp,ncIp):
    ret = False
    if ccIp != None:
        try:
            transport = TSocket.TSocket(ccIp,thd_port.THRIFT_CC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clusterApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_nc_heart_beat(ncIp)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_nc_heart_beat error:%s' % (tx.message))
    return ret      

def p_regnc_set_cc_global(ccIp,ncIp):
    ret = False
    if ccIp != None:
        try:
            transport = TSocket.TSocket(ccIp, thd_port.THRIFT_CC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clusterApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_init_nc_global_info(ncIp)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_regnc_set_cc_global error:%s' % (tx.message))
    return ret

#===============================
#   NC Thrift Interfaces
#===============================

def get_instance_transaction_list(nodeIp,userName):
    transactions = []
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        transactions = client.euca_get_run_instance_transaction_list(userName)
        transport.close()
    except Thrift.TException, tx:
		logging.warn('get_instance_transaction_list error:%s' %tx.message)
    return transactions

def get_instance_states(nodeIp,userName):
    instances = []
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        instances = client.luhya_res_get_instance_states(userName)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('get_instance_transaction_list error:%s' %tx.message)
    return instances


def check_instance_is_running(nodeIp,user,imageId):
    ret=False
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_nc_instance_is_running(user,imageId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('check_instance_is_running error:%s' %tx.message)
    return ret
    
def add_migrage_transaction(nodeIp,transaction):
    ret=False
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_nc_add_migrage_transaction(transaction)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('add_migrage_transaction error:%s' %tx.message)
    return ret
        
def p_nc_auto_migrate_receive_vms(nodeIp, migratevmLists):
    ret=False
    try:
        socket = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_nc_auto_migrate_receive_vms(migratevmLists)
        transport.close()
    except Thrift.TException, tx:
        logger.error('p_nc_update_live_vm_list exception:%s'%tx.message)  
    return ret

def p_nc_is_live(nodeIp):
    ret=False
    try:
        socket = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(socket)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_nc_is_live()
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_nc_is_live error:%s'%tx.message)
    return ret
    
def p_backup_instance(nodeIp ,userName,imageID):
    ret = True	
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_backup_instance(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
		logging.warn('p_backup_instance error:%s' %tx.message)
    return ret
   
def p_stop_backup_instance(nodeIp ,userName,imageID):
    ret = True	
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_stop_backup_instance(userName,imageID)
        transport.close()
    except Thrift.TException, tx:
		logging.warn('p_stop_backup_instance error:%s' %tx.message)
    return ret    
    
def p_get_backup_time(nodeIp,user,imageID):
    ret = 0	
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_get_backup_time(user,imageID)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_get_backup_time error:%s' %tx.message)
        ret = 0
    return ret

	
def p_restore_instance(node_ip ,user_name,image_id):
    ret = True	
    try:
        transport = TSocket.TSocket(node_ip, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_restore_instance(user_name, image_id)
        transport.close()
    except Thrift.TException, tx:
        logging.warn('p_restore_instance error:%s' %tx.message)
        ret = False
    return ret	


    

#to run instance ,from nc  
def p_nc_start_vm(nodeIp,clientInfo):
    ret = -1
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_start_vm(clientInfo)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_cc_start_vm error:%s' % (tx.message))    
    return ret     

def p_nc_stop_vm(node_ip,client_info):
    ret = True
    if client_info!=None :
        try:
            transport = TSocket.TSocket(node_ip, thd_port.THRIFT_NC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = nodeApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_stop_vm(client_info)
            transport.close()
        except Thrift.TException, tx:
            logging.warn( 'p_nc_stop_vm error:%s' % (tx.message))
            ret = False
    return ret

    
def p_runInstance(nodeIp,transactionID):
    ret = -6
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.euca_res_runInstance( transactionID )
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_runInstance error:%s' % (tx.message))    
    return ret

def p_get_transId(nodeIp,user,imageId):
    transId = None
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        transId = client.luhya_res_nc_get_transId_by_user_image(user,imageId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_get_transId error:%s' % (tx.message))
    return transId

def p_stop_instance(node_ip,user,image_id):
    ret = True
    try:
        transport = TSocket.TSocket(node_ip, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_stop_instance(user,image_id)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_stop_instance error:%s' % (tx.message))
        ret = False
    return ret

def p_restart_instance(nodeIp,user,imageId):
    ret = -1
    instanceId = (imageId[4:len(imageId)] + user)[0:15]
    try:
        transport = TSocket.TSocket(nodeIp, thd_port.THRIFT_NC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = nodeApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_nc_reboot_instance(instanceId)
        transport.close()
    except Thrift.TException, tx:
        logging.warn( 'p_restart_instance error:%s' % (tx.message))
        ret = -2
    return ret    


