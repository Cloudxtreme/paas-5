import sys
sys.path.append("/usr/lib/python2.6/site-packages")
import hashlib
import time
import threading
from cloudbot.interface.ttypes import *
from cloudbot.utils import OpenLdap,utility
import vmConfigEngine
import copy
import vmEngineUtility

logger = utility.init_log()



# change the image ,update the clc global clientData 
#p_change_image_update_client_data
def p_update_clientdata_by_image(newImage,clientDataList):
    for userName in clientDataList.keys():
        if clientDataList[userName].has_key('remote'):
            clientDatas = clientDataList[userName]['remote']
            for clientData in clientDatas:
                if clientData.image_id == newImage.imageId:
                    clientData.os_type = newImage.OS
                    clientData.platform = newImage.platform
                    clientData.image_category = newImage.imageCategory 
                    clientData.image_name = newImage.name                   
        
        if clientDataList[userName].has_key('local'):
            for nodeIp in clientDataList[userName]['local'].keys():
                clientDatas = clientDataList[userName]['local'][nodeIp]
                for clientData in clientDatas:
                    if clientData.image_id == newImage.imageId:
                        clientData.os_type = newImage.OS
                        clientData.platform = newImage.platform
                        clientData.image_category = newImage.imageCategory
                        clientData.image_name = newImage.name                
    return

# change the image ,update the clc global instance info
#old p_change_image_update_instances
def p_update_instances_by_image(newImage,instanceList):
    for cluster in instanceList.keys():
        for nodeIp in instanceList[cluster].keys():
            clientDatas = instanceList[cluster][nodeIp]
            for clientData in clientDatas:
                if clientData.image_id == newImage.imageId:
                    clientData.os_type = newImage.OS
                    clientData.platform = newImage.platform
                    clientData.image_category = newImage.imageCategory
                    clientData.image_name = newImage.name
                    
    return

#create the client info from the vmconfig 
#the vmconfig is set user and imageId
#vmconfig like : user=<userName>,image=<imageId>
def add_vmconfig(vmconfig,images,nodeList,clientDataList):       
    img = vmEngineUtility.get_imageinfo(vmconfig.image_id,images)  #vmEngineUtility.
    if img==None:
        logger.debug('init_client_info : no image')
        return
    logger.debug('init_client_info image:%s' %str(img))    
    clientInfo = thd_client_info()
    clientInfo.image_id = vmconfig.image_id
    clientInfo.user = vmconfig.user
    clientInfo.vmconfig_id = vmconfig.id
    clientInfo.image_name = img.name
    clientInfo.client_data_id = vmEngineUtility.create_clientdata_id(vmconfig.user,vmconfig.image_id)
    clientInfo.is_assign_node = vmconfig.is_assign_node
    if vmconfig.is_assign_node:
        clientInfo.node_ip = vmconfig.node_ip
    else:
        clientInfo.node_ip = 'any'
    if vmconfig.thermophoresis!=None: 
        clientInfo.thermophoresis=copy.deepcopy(vmconfig.thermophoresis)
    if vmconfig.net_info!=None: 
        clientInfo.net_info = copy.deepcopy(vmconfig.net_info)
    if vmconfig.run_schedule!=None:
        clientInfo.run_schedule = copy.deepcopy(vmconfig.run_schedule)
    if vmconfig.vm_info!=None:
        clientInfo.vm_info = copy.deepcopy(vmconfig.vm_info)
        if not vmconfig.is_assign_node:
            clientInfo.vm_info.is_run_without_copy = True
        if vmconfig.vm_info.machine_name==None:
            clientInfo.vm_info.machine_name = img.name
    if vmconfig.snapshot!=None:
        clientInfo.snapshot = copy.deepcopy(vmconfig.snapshot)
    if vmconfig.peripheral!=None:
        clientInfo.peripheral = copy.deepcopy(vmconfig.peripheral)
    instanceState= thd_instance_state()
    instanceState.instance_type= img.imageType
    instanceState.is_can_run = True
    instanceState.download_progress = -1
    instanceState.state = thd_TRANSACT_STATE.TERMINATED
    instanceState.is_local = False
    isRemoteNode = True
    if vmconfig.is_assign_node:
        nodeInfo = vmEngineUtility.get_nodeinfo(vmconfig.node_ip,nodeList)
        if nodeInfo!=None and nodeInfo.isLocal!=None and nodeInfo.isLocal:        
            instanceState.is_local = True
            isRemoteNode = False
    clientInfo.instance_state = instanceState
    clientInfo.os_type = img.OS
    clientInfo.platform = img.platform
    clientInfo.image_category = img.imageCategory
    clientInfo.image_size = img.size
    clientInfo.user_department_id = vmconfig.user_department_id
    logger.debug('the clientInfo: %s' %str(clientInfo))
    vmEngineUtility.add_clientinfo_to_dictionary(clientInfo,clientDataList)
    logger.debug('init_client_info :%s' %str(clientDataList))
    return

#old: p_update_clientinfo_from_vmconfig
def p_update_clientinfo_by_vmconfig(clientInfo,newVmConfig):
    logger.debug('p_update_clientinfo_by_vmconfig vmconfig:%s' %str(newVmConfig))        
    clientInfo.is_assign_node = newVmConfig.is_assign_node
    if newVmConfig.is_assign_node:
        clientInfo.node_ip = newVmConfig.node_ip
    else:
        clientInfo.node_ip = 'any'
    if newVmConfig.thermophoresis!=None:
        clientInfo.thermophoresis=copy.deepcopy(newVmConfig.thermophoresis)
    if newVmConfig.net_info!=None:
        clientInfo.net_info = copy.deepcopy(newVmConfig.net_info)        
    if newVmConfig.run_schedule!=None:
        clientInfo.run_schedule = copy.deepcopy(newVmConfig.run_schedule)    
    if newVmConfig.vm_info!=None:
        vmInfo = copy.deepcopy(newVmConfig.vm_info)
        if newVmConfig.vm_info.machine_name==None:            
            vmInfo.machine_name = clientInfo.vm_info.machine_name
        if not newVmConfig.is_assign_node:
            vmInfo.is_run_without_copy = True
        clientInfo.vm_info = vmInfo
    if newVmConfig.snapshot!=None:
        clientInfo.snapshot = copy.deepcopy(newVmConfig.snapshot)        
    if newVmConfig.peripheral!=None:
        clientInfo.peripheral = copy.deepcopy(newVmConfig.peripheral)    
    return

# add the image ,update the clc global clientData info and global instance info
def add_image(newImage,clientDataList):
    return

# change the image ,update the clc global clientData info and global instance info
def change_image(newImage,clientDataList,instanceList):
    p_update_clientdata_by_image(newImage,clientDataList)
    p_update_instances_by_image(newImage,instanceList)
    
def delete_image(imageId,clientDataList):
    for userName in clientDataList.keys():     
        # delete remote node clientdata about image
        if clientDataList[userName].has_key('remote'):
            clientInfoList = clientDataList[userName]['remote'][:]
            for clientInfo in clientInfoList:
                if clientInfo.image_id==imageId:
                    if not vmConfigEngine.g_user_thread_lock.has_key(userName):
                        vmConfigEngine.g_user_thread_lock[userName]=threading.Lock()                
                    vmConfigEngine.g_user_thread_lock[userName].acquire()
                    clientDataList[userName]['remote'].remove(clientInfo)
                    vmConfigEngine.g_user_thread_lock[userName].release()
        #delete local node clientdata about image            
        if clientDataList[userName].has_key('local'):
            clientDataLocalList = clientDataList[userName]['local']
            for nodeIp in clientDataLocalList.keys():
                clientInfoList = clientDataLocalList[nodeIp][:]
                for clientInfo in clientInfoList:
                    if clientInfo.image_id==imageId:
                        if not vmConfigEngine.g_user_thread_lock.has_key(userName):
                            vmConfigEngine.g_user_thread_lock[userName]=threading.Lock()
                        vmConfigEngine.g_user_thread_lock[userName].acquire()
                        clientDataList[userName]['local'][nodeIp].remove(clientInfo)
                        vmConfigEngine.g_user_thread_lock[userName].release()                
    return        
        
# change vmconfig ,update the clc global clientData info and global instance info
def change_vmconfig(newVmConfig,images,nodeList,userList,clientDataList):
    if clientDataList.has_key(newVmConfig.user):
        #vmconfig assigned node is local node
        if clientDataList[newVmConfig.user].has_key('local'):
            for nodeIp in clientDataList[newVmConfig.user]['local'].keys():
                clientInfoList = clientDataList[newVmConfig.user]['local'][nodeIp]
                for clientInfo in clientInfoList:
                    if clientInfo.vmconfig_id==newVmConfig.id:
                        vmConfigEngine.g_user_thread_lock[newVmConfig.user].acquire()
                        clientDataList[newVmConfig.user]['local'][nodeIp].remove(clientInfo)
                        vmConfigEngine.g_user_thread_lock[newVmConfig.user].release()
                                 
        #vmconfig assigned node is remote node
        if clientDataList[newVmConfig.user].has_key('remote'):
            clientInfoList = clientDataList[newVmConfig.user]['remote']
            for clientInfo in clientInfoList:
                if clientInfo.vmconfig_id==newVmConfig.id:
                    vmConfigEngine.g_user_thread_lock[newVmConfig.user].acquire()
                    clientDataList[newVmConfig.user]['remote'].remove(clientInfo)
                    vmConfigEngine.g_user_thread_lock[newVmConfig.user].release()
                    
    add_vmconfig(newVmConfig,images,nodeList,clientDataList)       
    return           
                            

def delete_vmconfig(vmconfigId,clientDataList):
    logger.debug('vmEngine11:delete_vmconfig')
    for userName in clientDataList.keys():
        #vmconfig assigned node is local node
        if clientDataList[userName].has_key('local'):
            for nodeIp in clientDataList[userName]['local']:
                clientInfoList = clientDataList[userName]['local'][nodeIp][:]
                for clientInfo in clientInfoList:
                    if clientInfo.vmconfig_id==vmconfigId:
                        #delete the instance
                        if vmConfigEngine.g_user_thread_lock.has_key(userName):
                            vmConfigEngine.g_user_thread_lock[userName]=threading.Lock()
                        vmConfigEngine.g_user_thread_lock[userName].acquire()
                        clientDataList[userName]['local'][nodeIp].remove(clientInfo)
                        vmConfigEngine.g_user_thread_lock[userName].release()                       

        #vmconfig assigned node is remote node or not assigned node
        if clientDataList[userName].has_key('remote'):   
            clientInfoList = clientDataList[userName]['remote'][:]
            for clientInfo in clientInfoList:
                if clientInfo.vmconfig_id==vmconfigId:
                    if vmConfigEngine.g_user_thread_lock.has_key(userName):
                        vmConfigEngine.g_user_thread_lock[userName]=threading.Lock()
                    vmConfigEngine.g_user_thread_lock[userName].acquire()
                    clientDataList[userName]['remote'].remove(clientInfo)
                    vmConfigEngine.g_user_thread_lock[userName].release()                        
    return True


def add_user(user,clientDataList):
    return

def delete_user(user,clientDataList):
    if clientDataList.has_key(user):
        if vmConfigEngine.g_user_thread_lock.has_key(user):
            vmConfigEngine.g_user_thread_lock[user]=threading.Lock()        
        vmConfigEngine.g_user_thread_lock[user].acquire()
        clientDataList.pop(user)
        vmConfigEngine.g_user_thread_lock[user].release()    
    return
