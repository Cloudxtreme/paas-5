import hashlib
import time
import copy
import uuid
from cloudbot.utils import utility

logger = utility.init_log()
#get the image info from image list by imageId
#old:p_get_image_by_imageId
def get_imageinfo(imageId , images):
    logger.debug('vmEngineUtility.get_imageinfo imagesId:%s' %imageId )
    img = None
    for image in images:
        if image.imageId ==imageId:
            img = copy.deepcopy(image)
            break
    return img

#get node info from node list by ip
#old: p_get_nodeinfo_by_ip
def get_nodeinfo(nodeIp,nodeList):
    ncInfo = None
    for nodeInfo in nodeList:
        if nodeInfo.hostIp == nodeIp:
            ncInfo = nodeInfo
            break
    return ncInfo

#is the user\imageId homologous clientdata is exisit in clientInfos
#old : p_get_find_clientinfo
def _is_clientinfo_exist(clientInfo,clientDataList):
    isFind = False
    clientInfos = []
    if _is_node_remote(clientInfo):
        if(clientDataList.has_key(clientInfo.user) and clientDataList[clientInfo.user].has_key('remote')):
            clientInfos = clientDataList[clientInfo.user]['remote']
    else:
        if clientDataList.has_key(clientInfo.user) and clientDataList[clientInfo.user].has_key('local') and clientDataList[clientInfo.user]['local'].has_key(clientInfo.node_ip):
            clientInfos = clientDataList[clientInfo.user]['local'][clientInfo.node_ip]
    logger.debug('vmEngineUtility : _is_clientinfo_exist %s' %str(clientInfos))
    for ci in clientInfos:
        if ci.image_id==clientInfo.image_id and ci.user==clientInfo.user:
            isFind = True
            break
    return isFind

#create the clientdata id
#old: p_create_client_id
def create_clientdata_id(user,imageId):
    m = hashlib.md5()
    m.update(str(uuid.uuid4())+user+imageId)
    return m.hexdigest().upper()[0:8]


def check_vmconfig(vmconfig):
    return True
    
def check_image(imageInfo):
    return True

def _is_node_remote(clientInfo):
    return not clientInfo.instance_state.is_local
        

def change_clientinfo():
    pass

def delete_clientinfo():
    pass

 
def add_clientinfo_to_dictionary(clientInfo,clientDataList):
    logger.debug('vmEngineUtility start')
    if _is_clientinfo_exist(clientInfo,clientDataList):              #is the clientinfo exisit in g_client_info
        logger.debug('vmEngineUtility.add_clientinfo_to_dictionary :clientinfo exist!')
        return
    logger.debug('vmEngineUtility.add_clientinfo_to_dictionary :clientinfo not exisit!')
    if _is_node_remote(clientInfo):                    #node is remote mode
        clientInfos = []
        if clientDataList.has_key(clientInfo.user):
            if clientDataList[clientInfo.user].has_key('remote'):
                clientDataList[clientInfo.user]['remote'].append(clientInfo)
            else:
                clientInfos.append(clientInfo)
                clientDataList[clientInfo.user]['remote'] = clientInfos
        else:
            clientInfos.append(clientInfo)
            userData={}
            userData['remote'] = clientInfos
            clientDataList[clientInfo.user] = userData                        
    else:                                     #node is local mode
        if clientDataList.has_key(clientInfo.user):
            if clientDataList[clientInfo.user].has_key('local'):
                if clientDataList[clientInfo.user]['local'].has_key(clientInfo.node_ip):
                    localClientInfos = clientDataList[clientInfo.user]['local'][clientInfo.node_ip]
                    clientDataList[clientInfo.user]['local'][clientInfo.node_ip].append(clientInfo)                    
                else:
                    logger.debug('clientDataList no ip key:%s' %clientInfo.node_ip)
                    localClientInfos = []
                    localClientInfos.append(clientInfo)
                    clientDataList[clientInfo.user]['local'][clientInfo.node_ip] = localClientInfos
            else:
                localClientDic = {}
                localClientInfos = []
                localClientInfos.append(clientInfo)
                localClientDic[clientInfo.node_ip] = localClientInfos
                clientDataList[clientInfo.user]['local'] = localClientDic
        else:
            localDic = {}
            localClientDic = {}
            localClientInfos = []
            localClientInfos.append(clientInfo)
            localClientDic[clientInfo.node_ip] = localClientInfos
            localDic['local'] = localClientDic
            clientDataList[clientInfo.user]=localDic    
            
            
def add_clientinfos_to_dictionary(clientInfos,clientDataList):
    for clientInfo in clientInfos:
        add_clientinfo_to_dictionary(clientInfo,clientDataList)

