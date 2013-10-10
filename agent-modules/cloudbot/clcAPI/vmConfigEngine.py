import sys
sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.interface.ttypes import *
from cloudbot.utils import OpenLdap,utility
import threading
import copy

import vmEngineUtility
import vmEngine00
import vmEngine11
from vmEngineType import *

#import vmEngine10
#import vmEngine01
#import vmEngine00

logger = utility.init_log()
g_user_thread_lock={}           # user lock to change global g_clientinfo_user
g_node_thread_lock={}           # node lock to change global g_instance_clc
    

def p_get_vmconfig_type(vmconfig):
    vmconfigType = -1
    if vmconfig.user!='any':
        if vmconfig.image_id!='any':
            if vmconfig.is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_111
            else: #not is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_110    
        else: #image_id=='any'
            if vmconfig.is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_101
            else: #not is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_100
    else: #user=='any':	
        if vmconfig.image_id!='any':
            if vmconfig.is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_011
            else: #not is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_010
        else: #image_id=='any'
            if vmconfig.is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_001
            else: #not is_assign_node:
                vmconfigType = VM_ENGINE.TYPE_000
    return vmconfigType


#order the vmconfig list
def p_order_vmconfig_list(vmconfigs):
    vmconfigList = []
    type_111_list = []
    type_110_list = []
    type_101_list = []
    type_100_list = []
    type_011_list = []
    type_010_list = []
    type_001_list = []
    type_000_list = []
	
    for vmconfig in vmconfigs:
        if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_111:
            type_111_list.append(vmconfig)
        else :
            if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_110:
                type_110_list.append(vmconfig)    
            else:
                if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_101:
                    type_101_list.append(vmconfig) 
                else:
                    if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_100:
                        type_100_list.append(vmconfig)    
                    else:
                        if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_011:
                            type_011_list.append(vmconfig)    
                        else:
                            if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_010:
                                type_010_list.append(vmconfig) 
                            else:
                                if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_001:
                                    type_001_list.append(vmconfig)               
                                else:
                                    if p_get_vmconfig_type(vmconfig)==VM_ENGINE.TYPE_000:
                                        type_000_list.append(vmconfig)

    vmconfigList = type_111_list + type_110_list + type_101_list + type_100_list + type_011_list + type_010_list + type_001_list + type_000_list    
    logger.debug('order vmconfig: %s' %str(vmconfigList))
    return vmconfigList

#create the client info from the vmconfig 
#old:p_init_client_info_from_vmconfig
def p_init_client_info(vmConfigList, imageList, userList, nodeList, clientDataList):
    logger.debug('p_init_clientInfo  vmConfigList: %s' %str(vmConfigList))       
    for vmconfig in vmConfigList:
        vmconfigType = p_get_vmconfig_type(vmconfig)
        logger.debug('init_client_info vmtype: %s' %str(vmconfigType))         
        if vmconfigType==VM_ENGINE.TYPE_111 or vmconfigType==VM_ENGINE.TYPE_110:    #g_clientinfo_user            
            vmEngine11.add_vmconfig(vmconfig, imageList, nodeList, clientDataList)            
#    elif vmconfig.user!='any' and vmconfig.image_id=='any':
#        vmEngine10.p_get_clientInfo_from_vmconfig_set_user(vmConfigList,nodeList,clientDataList)
#    elif vmconfig.user=='any' and vmconfig.image_id!='any':
#        vmEngine01.p_get_clientInfo_from_vmconfig_set_image(vmConfigList,imageList,nodeList,clientDataList)    
        elif vmconfigType==VM_ENGINE.TYPE_001 or vmconfigType==VM_ENGINE.TYPE_000:
            logger.debug('init_client_info 00 vmconfig is: %s' %str(vmconfig)) 
            vmEngine00.add_vmconfig(vmconfig,imageList,userList,nodeList,clientDataList)
            logger.debug('init_client_info 00 clientDataList is: %s' %str(clientDataList))    
        else:
            pass

# init the clc global clientdata
def init_client_info(vmEngineData, clientDataList):
    if vmEngineData.nodeList!=None and len(vmEngineData.nodeList)>0:
        for nodeInfo in vmEngineData.nodeList:
            if not g_node_thread_lock.has_key(nodeInfo.hostIp):
                g_node_thread_lock[nodeInfo.hostIp] = threading.Lock()
    if vmEngineData.userList!=None:
        for userInfo in vmEngineData.userList:
            if not g_user_thread_lock.has_key(userInfo.userName):
                g_user_thread_lock[userInfo.userName]=threading.Lock()
    #order the vmconfig
    vmEngineData.vmconfigs = p_order_vmconfig_list(vmEngineData.vmconfigs)
    #do init 	
    p_init_client_info(vmEngineData.vmconfigs, vmEngineData.images,vmEngineData.userList, vmEngineData.nodeList, clientDataList)

#change the global instance list 
#old:p_update_global_state_instances
def p_update_global_instances_state(clientData,nodeList,instanceList):
    if clientData.user==None or clientData.image_id==None or clientData.node_ip==None:
        logger.warn('p_update_global_instances_state : user imageID or nodeIp is none!')
        return
    clusterName = None
    nodeInfo = vmEngineUtility.get_nodeinfo(clientData.node_ip,nodeList)
    if nodeInfo!=None:
        logger.debug('p_update_global_instances_state : the node is %s' %str(nodeInfo))        
        clusterName = nodeInfo.clusterName
        logger.debug('p_update_global_instances_state : the clusterName %s' %clusterName) 
    if clusterName!=None:
        if not g_node_thread_lock.has_key(clientData.node_ip):
            g_node_thread_lock[clientData.node_ip]=threading.Lock()
        g_node_thread_lock[clientData.node_ip].acquire()        
        if instanceList.has_key(clusterName):
            logger.debug('p_update_global_instances_state : has cluster key' )
            p_cluster = instanceList[clusterName]
            if p_cluster.has_key(clientData.node_ip):
                instances = p_cluster[clientData.node_ip]
                hasIns = False
                for insClient in instances:
                    if insClient.image_id ==clientData.image_id and insClient.user == clientData.user :
                        hasIns = True
                        insClient.instance_state.state = clientData.instance_state.state                        
                        break
                if not hasIns:                    
                    instances.append(clientData)
                    
            else:
                instances=[]
                instances.append(clientData)
                instanceList[clusterName][clientData.node_ip]=instances
        else:
            logger.debug('p_update_global_instances_state : no cluster key' )
            instances=[]
            instances.append(clientData)            
            nodeIns = {}
            nodeIns[clientData.node_ip] = instances
            instanceList[clusterName]=nodeIns
        g_node_thread_lock[clientData.node_ip].release()
    logger.debug('p_update_global_instances_state : the instanceList is %s' %str(instanceList))
    return    

# delete the instance : the clientinfo homologous instance
def p_delete_global_instances(clientinfo,nodeInfo,instanceList):
    if clientinfo.user==None or clientinfo.image_id==None or clientinfo.node_ip==None or nodeInfo==None or nodeInfo.clusterName==None:
        logger.warn('p_delete_global_instances : user imageID or nodeIp is none!')
        return   

    if not g_node_thread_lock.has_key(clientinfo.node_ip):
        g_node_thread_lock[clientinfo.node_ip]=threading.Lock()
    g_node_thread_lock[clientinfo.node_ip].acquire()        
    if instanceList.has_key(nodeInfo.clusterName): 
        if instanceList[nodeInfo.clusterName].has_key(clientinfo.node_ip):
            insClients =instanceList[nodeInfo.clusterName][clientinfo.node_ip][:]
            for insclient in insClients:
                if insclient.user == clientinfo.user and insclient.image_id==clientinfo.image_id:
                    instanceList[nodeInfo.clusterName][clientinfo.node_ip].remove(insclient)
                    break
    g_node_thread_lock[clientinfo.node_ip].release()

    return       
            
# change the state of clientdata
#old p_update_global_state_clientdatas
def p_update_global_clientdatas_state(runInstanceData,images,nodeList,clientDataList,instanceList,state):
    logger.debug('p_update_global_clientdatas_state start')
    user = runInstanceData.user
    imageID = runInstanceData.image_id
    nodeIp = runInstanceData.node_ip
    strinfo = 'user: '+user+' imageID: '+imageID+' nodeIp: '+nodeIp
    logger.debug('p_update_global_clientdatas_state:%s' %str(strinfo))
    nodeInfo = vmEngineUtility.get_nodeinfo(nodeIp,nodeList)
    if nodeInfo.isLocal:
        if clientDataList.has_key(user) and clientDataList[user].has_key('local') and clientDataList[user]['local'].has_key(nodeIp) :
            clientinfos = clientDataList[user]['local'][nodeIp]
            for cl in clientinfos:
                if cl.image_id == imageID:
                    g_user_thread_lock[user].acquire()
                    cl.node_ip = nodeIp
                    cl.instance_state.state = state
                    g_user_thread_lock[user].release()
                    p_update_global_instances_state(cl,nodeList,instanceList)
                    break
    else:
        if clientDataList.has_key(user) and clientDataList[user].has_key('remote'):
            clientinfos = clientDataList[user]['remote']
            for cl in clientinfos:
                if cl.image_id == imageID:
                    g_user_thread_lock[user].acquire()
                    cl.node_ip = nodeIp
                    cl.instance_state.state = state
                    g_user_thread_lock[user].release()
                    clInfo = copy.deepcopy(cl)
                    p_update_global_instances_state(clInfo,nodeList,instanceList)
                    logger.debug('p_update_global_clientdatas_state : %s' %str(cl))
                    break            

# when start instance , change the clc global state
def update_global_by_startvm(runInstanceData,images,nodeList,clientDataList,instanceList):
    p_update_global_clientdatas_state(runInstanceData,images,nodeList,clientDataList,instanceList,thd_TRANSACT_STATE.DOWNLOADING)

# get the transaction fron cc , update the clc global clientData and instance info
def update_global_by_transactions(transmitData,nodeList,clientDataList,instanceList):
    logger.debug('update_global_by_transactions :%s' %str(transmitData))
    nodeInfo = vmEngineUtility.get_nodeinfo(transmitData.node_ip,nodeList)
    if nodeInfo==None:
        logger.error('the node not register: %s' %transmitData.node_ip)
        return
    logger.debug('clientData :%s' %str(clientDataList))
    for user in clientDataList.keys():
        p_clientinfos=None
        if nodeInfo.isLocal!=None and nodeInfo.isLocal:
            if clientDataList[user].has_key('local') and clientDataList[user]['local'].has_key(transmitData.node_ip):
                p_clientinfos = clientDataList[user]['local'][transmitData.node_ip]
        else:
            if clientDataList[user].has_key('remote'):
                p_clientinfos = clientDataList[user]['remote']                    
            
        if p_clientinfos!=None:
            for clientinfo in p_clientinfos:
                if clientinfo.node_ip ==transmitData.node_ip :
                    clientHasTrac = False
                    if len(transmitData.transactions)>0:                    
                        for transaction in transmitData.transactions:
                            if(transaction.user==clientinfo.user and transaction.imageID==clientinfo.image_id):
                                clientHasTrac = True
                                if not g_user_thread_lock.has_key(user):
                                    g_user_thread_lock[user]=threading.Lock()  
                                g_user_thread_lock[user].acquire()
                                if clientinfo.instance_state.state==thd_TRANSACT_STATE.DOWNLOADING : 
                                    if transaction.state!=thd_TRANSACT_STATE.TERMINATED :                            
                                        clientinfo.instance_state.state = transaction.state
                                else:
                                    if clientinfo.instance_state.state==thd_TRANSACT_STATE.SHUTTING_DOWN :
                                    #instance from shuitingdown to terminated,the transit state not set to client data
                                        if transaction.state == thd_TRANSACT_STATE.TERMINATED:
                                            clientinfo.instance_state.state = transaction.state
                                    else:
                                        clientinfo.instance_state.state = transaction.state
                                clientinfo.vm_info.vm_port = transaction.instancePort
                                clientinfo.vm_info.vm_password = transaction.instancePassword
                                clientinfo.instance_state.download_progress = transaction.downloadProgress                                                                
                                g_user_thread_lock[user].release()
                                logger.debug('clientInfo: %s' %str(clientinfo))
                                p_update_global_instances_state(clientinfo,nodeList,instanceList)
                            
                    if not clientHasTrac:
                        if not g_user_thread_lock.has_key(user):
                            g_user_thread_lock[user]=threading.Lock()  
                        g_user_thread_lock[user].acquire()
                        clientinfo.instance_state.state = thd_TRANSACT_STATE.TERMINATED
                        clientinfo.vm_info.vm_port = -1
                        clientinfo.vm_info.vm_password = None
                        clientinfo.instance_state.download_progress = -1                                
                        g_user_thread_lock[user].release()                        
                        p_delete_global_instances(clientinfo,nodeInfo,instanceList)
    logger.debug(' clientdata info:%s' %str(clientDataList))    

def add_image(imageInfo,clientDataList):
    vmEngine11.add_image(imageInfo,clientDataList)
    
    
# delete the image ,update the clc global clientData and instance info    
def delete_image(imageId,clientDataList):
    vmEngine11.delete_image(imageId,clientDataList)

# change the image ,update the clc global clientData info and global instance info
def change_image(newImage,clientDataList,instanceList):
    vmEngine11.change_image(newImage,clientDataList,instanceList)

# add vmconfig ,update the clc global clientData info and global instance info    
def add_vmconfig(newVmConfig,images,nodeList,userList,clientDataList):
    vmconfigType = p_get_vmconfig_type(newVmConfig)
    if vmconfigType==VM_ENGINE.TYPE_111 or vmconfigType==VM_ENGINE.TYPE_110:
        vmEngine11.add_vmconfig(newVmConfig,images,nodeList,clientDataList)
    elif vmconfigType==VM_ENGINE.TYPE_001 or vmconfigType==VM_ENGINE.TYPE_000:
        vmEngine00.add_vmconfig(newVmConfig,images,userList,nodeList,clientDataList)
    return

# delete vmconfig ,update the clc global clientData info and global instance info
def delete_vmconfig(vmconfigId,clientDataList):
    vmEngine11.delete_vmconfig(vmconfigId,clientDataList)

# change vmconfig ,update the clc global clientData info and global instance info
def change_vmconfig(newVmConfig,images,nodeList,userList,clientDataList):
    vmconfigType = p_get_vmconfig_type(newVmConfig)
    if vmconfigType==VM_ENGINE.TYPE_111 or vmconfigType==VM_ENGINE.TYPE_110:
        vmEngine11.change_vmconfig(newVmConfig,images,nodeList,userList,clientDataList)
    elif vmconfigType==VM_ENGINE.TYPE_001 or vmconfigType==VM_ENGINE.TYPE_000:
        vmEngine00.change_vmconfig(newVmConfig,images,nodeList,userList,clientDataList)
    else:
        pass
    return                           
    
def add_user(user,vmconfigs,clientDataList):
    for vmconfig in vmconfigs:
        vmconfigType = p_get_vmconfig_type(vmconfig)
        if vmconfigType==VM_ENGINE.TYPE_111 or vmconfigType==VM_ENGINE.TYPE_110:
            vmEngine11.add_user(user,vmconfig,clientDataList)
        elif vmconfigType==VM_ENGINE.TYPE_001 or vmconfigType==VM_ENGINE.TYPE_000:
            vmEngine00.add_user(user,vmconfig,clientDataList)

def delete_user(user,clientDataList):
    vmEngine11.delete_user(user,clientDataList)
    
