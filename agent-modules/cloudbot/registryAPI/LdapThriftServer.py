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
from cloudbot.interface import ldapApi
from cloudbot.interface.ttypes import *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer


import string
import ldap
import ldap.modlist as modlist
import getopt, sys, os, stat ,copy
from cloudbot.utils import OpenLdap,utility
import logging
import threading
import thread
import uuid

import hashlib
import time
import base64
import re
from cloudbot.utils.const_def import *


g_server_resource = {'recvRate':0,'sendRate':0,'cpuUtilization':0}
g_source_switch = threading.Lock()
featurelist = {}
logger = utility.init_log()
g_clc_ip = None
g_ldap_ip = None
g_user_name = None
g_user_passwd = None

class p_heart_beat_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        p_heart_beat_timer()


class p_transmit_server_source_thread(threading.Thread):
    def __init__(self, ):
        threading.Thread.__init__(self)

    def run(self):
        logger.info('p_transmit_server_source_thread...')
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
                OpenLdap.p_transmit_hard_source(g_clc_ip,g_ldap_ip,hdSource)
            time.sleep(SERVER_SOURCE_INTV)

def p_get_ldap_info():
    return g_ldap_ip,g_user_name,g_user_passwd

def p_get_ldap_logoninfo():    
    fh = os.popen('cat ' + LDAP_CONF_FILE)
    setconfig = 1
    for ln in fh.readlines():
        if 'LDAP_SERVER' in ln:
            ln = ln.strip(' \n')
            ls = ln.rsplit('"')
            ldapip = ls[1]
            setconfig = 0
        if 'LDAP_USER' in ln:
            ln = ln.strip(' \n')
            ls = ln.rsplit('"')
            username = ls[1]
        if 'LDAP_PASSWORD' in ln:
            ln = ln.strip(' \n')
            ls = ln.rsplit('"')
            password = ls[1]
    if(setconfig):
        return None
    return ldapip, username, password


def p_login_ldap(ldapip, username, password):
    try:
        l = ldap.open(ldapip)
        l.protocol_version = ldap.VERSION3
        l.simple_bind(username, password)
    except  ldap.LDAPError, e:
        return None
    return l


# get single value
def p_get_value_from_ldap(ldapip, username, password, baseDN, searchFilter, key):
    ncldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    resValue = None
    if (ncldap != None):
        try:
            ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
            result_set = []
            result_type, result_data = ncldap.result(ldap_result_id, 0)
            if (result_data != None):
                result_set.append(result_data)
            for l in result_set:
                if(l != None):
                    for ll in l:
                        lll = ll[1]
                        if lll.has_key(key):
                            resValue = lll.get(key)[0]
                            break
        except ldap.LDAPError, e:
            return None
        ncldap.unbind_s()
    return resValue

# get multi value  
def p_get_value_set_from_ldap(ldapip, username, password, baseDN, searchFilter, key):
    ncldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    resValues = None
    if (ncldap != None):
        try:
            ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
            result_set = []
            result_type, result_data = ncldap.result(ldap_result_id, 0)
            if (result_data != None):
                result_set.append(result_data)
            for l in result_set:
                if(l != None):
                    for ll in l:
                        lll = ll[1]
                        if lll.has_key(key):
                            resValues = lll.get(key)
                            break
        except ldap.LDAPError, e:
            return None
        ncldap.unbind_s()
    return resValues


def p_get_res_from_ldap(ldapip, username, password, baseDN, searchFilter, attrIDList):
    curldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    retvalue = {}
    if(curldap != None):
        try:
            ldap_result_id = curldap.search(baseDN, searchScope, searchFilter, attrIDList)
            result_set = []
            while 1:
                result_type, result_data = curldap.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
                    if len(result_set) > 0 and len(result_set[0][0][1]) > 0:
                        if attrIDList is None:
                            attrIDList = result_set[0][0][1].keys()
                        for attr in attrIDList:
                            retvalue[attr] = result_set[0][0][1].get(attr)
        except ldap.LDAPError, e:
            retvalue = {}
        curldap.unbind_s()
    return retvalue


def p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, attrIDList):
    curldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    result_set = []
    if(curldap != None):
        try:
            ldap_result_id = curldap.search(baseDN, searchScope, searchFilter, attrIDList)
            while 1:
                result_type, result_data = curldap.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                else:
                    if result_type == ldap.RES_SEARCH_ENTRY:
                        result_set.append(result_data)
        except ldap.LDAPError, e:
            logger.error('p_get_resultSet_from_ldap:%s' % (e.message))
            result_set = []
        curldap.unbind_s()
    return result_set


def p_add_to_ldap(newDN, attrs):
    ret = False
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    l = p_login_ldap(ldapip, ldapusername, ldappassword)
    if(l != None):
        try:
            ldif = modlist.addModlist(attrs)
            l.add_s(newDN, ldif)
            ret = True
        except ldap.LDAPError, e:
            logger.error('p_add_to_ldap:%s' % (e.message))
        l.unbind_s()
    return ret


def p_get_query_id(ldapip, username, password, userName):
    queryid = None
    userRes = p_get_resultSet_from_ldap(ldapip, username, password, AUTH_INFO_BASEDN, 'uuid=*', None)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for userInfo in userRes:
            if userInfo[0][1].get('UserNAME') != None:
                if userInfo[0][1].get('UserNAME')[0] == userName:
                    queryid = userInfo[0][1].get('queryId')[0]
    return queryid


def p_get_secert_key(ldapip, username, password, userName):
    secertkey = None
    userRes = p_get_resultSet_from_ldap(ldapip, username, password, AUTH_INFO_BASEDN, 'uuid=*', None)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for userInfo in userRes:
            if userInfo[0][1].get('UserNAME') != None:
                if userInfo[0][1].get('UserNAME')[0] == userName:
                    secertkey = userInfo[0][1].get('secretKey')[0]
    return secertkey


def p_getCategoryList(ldapip, username, password, baseDN, searchFilter):
    categoryList = []
    catRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(catRes) > 0 and len(catRes[0][0][1]) > 0:
        for category in catRes:
            if category[0][1].get('cn') != None:
                categoryList.append(category[0][1].get('cn')[0])
    return categoryList


def p_getImageTypeList(ldapip, username, password, baseDN, searchFilter):
    ImageTypeList = []
    catRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(catRes) > 0 and len(catRes[0][0][1]) > 0:
        for imgtype in catRes:
            if imgtype[0][1].get('ImageStyle') != None:
                ImageTypeList.append(imgtype[0][1].get('ImageStyle')[0])
    return ImageTypeList


def p_getOSTypeList(ldapip, username, password, baseDN, searchFilter):
    OSTypeList = []
    catRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(catRes) > 0 and len(catRes[0][0][1]) > 0:
        for ostype in catRes:
            if ostype[0][1].get('OSName') != None:
                OSTypeList.append(ostype[0][1].get('OSName')[0])
    return OSTypeList


def p__get_users_by_department(department):
    ldapip, username, password = p_get_ldap_info()
    users = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, 'seriesNAME=' + department)
    return users

def p_get_max_private_instances(user):
    logger.info('p_get_max_private_instances: %s'%user)
    max_private_instances = 1
    ldapip, username, password = p_get_ldap_info()
    value = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + user, 'MaxPrivateInstances')
    logger.info('p_get_max_private_instances: %s'%value)
    '''userRes = p_get_resultSet_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=' + user, None)
    logger.info('p_get_max_private_instances: %s'%userRes)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for userInfo in userRes:
            if userInfo[0][1].get('MaxPrivateInstances') != None:
                max_private_instances = string.atoi(userInfo[0][1].get('MaxPrivateInstances')[0])
            break'''
    if value != None:
        max_private_instances = int(value)
    return max_private_instances
    
def p_getUserList(ldapip, username, password, baseDN, searchFilter):
    usetList = []
    userRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for userInfo in userRes:
            userName = None
            if userInfo[0][1].get('UserNAME') != None:
                userName = userInfo[0][1].get('UserNAME')[0]
            email = None
            if userInfo[0][1].get('email') != None:
                email = userInfo[0][1].get('email')[0]
            realName = None
            if userInfo[0][1].get('realNAME') != None:
                realName = userInfo[0][1].get('realNAME')[0]
            reservationId = 0
            bCryptedPassword = None
            if userInfo[0][1].get('userPassword') != None:
                bCryptedPassword = userInfo[0][1].get('userPassword')[0]
            telephoneNumber = None
            if userInfo[0][1].get('telephoneNumber') != None:
                telephoneNumber = userInfo[0][1].get('telephoneNumber')[0]
            affiliation = None
            if userInfo[0][1].get('affiliation') != None:
                affiliation = userInfo[0][1].get('affiliation')[0]
            projectDescription = None
            if userInfo[0][1].get('projectDescription') != None:
                projectDescription = userInfo[0][1].get('projectDescription')[0]
            projectPIName = None
            if userInfo[0][1].get('projectPINAME') != None:
                projectPIName = userInfo[0][1].get('projectPINAME')[0]
            confirmationCode = None
            if userInfo[0][1].get('confirmetionCode') != None:
                confirmationCode = userInfo[0][1].get('confirmetionCode')[0]
            certificateCode = None
            if userInfo[0][1].get('certificateCode') != None:
                certificateCode = userInfo[0][1].get('certificateCode')[0]
            popedom = 0
            if userInfo[0][1].get('popedom') != None:
                popedom = int(userInfo[0][1].get('popedom')[0])
            isApproved = False
            if userInfo[0][1].get('isApproved') != None:
                if userInfo[0][1].get('isApproved')[0] == 'TRUE' or userInfo[0][1].get('isApproved')[0] == 'true':
                    isApproved = True
            isConfirmed = False
            if userInfo[0][1].get('isConfirmed') != None:
                if userInfo[0][1].get('isConfirmed')[0] == 'TRUE' or userInfo[0][1].get('isConfirmed')[0] == 'true':
                    isConfirmed = True
            isEnabled = False
            if userInfo[0][1].get('isEnable') != None:
                if userInfo[0][1].get('isEnable')[0] == 'TRUE' or userInfo[0][1].get('isEnable')[0] == 'true':
                    isEnabled = True
            isAdministrator = False
            if popedom == int(ADMIN_POPEDOM):
                isAdministrator = True
            passwordExpires = 0
            if userInfo[0][1].get('passwordExpires') != None:
                passwordExpires = string.atoi(userInfo[0][1].get('passwordExpires')[0])
            sLogonName = None
            if userInfo[0][1].get('displayName') != None:
                sLogonName = userInfo[0][1].get('displayName')[0]
            sSeriesName = None
            if userInfo[0][1].get('seriesNAME') != None:
                sSeriesName = userInfo[0][1].get('seriesNAME')[0]
            seriesID = 0
            if userInfo[0][1].get('seriesID') != None:
                seriesID = string.atoi(userInfo[0][1].get('seriesID')[0])
            maxPrivateInstances = 1
            if userInfo[0][1].get('MaxPrivateInstances') != None:
                maxPrivateInstances = string.atoi(userInfo[0][1].get('MaxPrivateInstances')[0])
            user = thd_UserInfo(\
                userName=userName,\
                email=email,\
                realName=realName,\
                bCryptedPassword=bCryptedPassword,\
                telephoneNumber=telephoneNumber,\
                affiliation=affiliation,\
                projectDescription=projectDescription,\
                projectPIName=projectPIName,\
                confirmationCode=confirmationCode,\
                certificateCode=certificateCode,\
                isApproved=isApproved,\
                isConfirmed=isConfirmed,\
                isEnabled=isEnabled,\
                isAdministrator=isAdministrator,\
                passwordExpires=passwordExpires,\
                popedom=popedom,\
                sLogonName=sLogonName,\
                sSeriesName=sSeriesName,\
                maxPrivateInstances=maxPrivateInstances,\
                seriesID=seriesID)
            usetList.append(user)
    return usetList


def p_judgeUser(userName, password):
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    popedom = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'cn=' + userName, 'popedom')
    logger.info('popedom: %s' % (str(popedom)))
    if(popedom != '2'):
        return False
    ldapPwd = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'cn=' + userName,
                                    'userPassword')
    if(ldapPwd == None):
        return False
    if(ldapPwd == password):
        return True
    else:
        return False


def p_getClusterList(ldapip, username, password, baseDN, searchFilter):
    ccList = []
    ccRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(ccRes) > 0 and len(ccRes[0][0][1]) > 0:
        for ccInfo in ccRes:
            clusterName = None
            if ccInfo[0][1].get('clusterName') != None:
                clusterName = ccInfo[0][1].get('clusterName')[0]
            hostIp = None
            if ccInfo[0][1].get('hostIPName') != None:
                hostIp = ccInfo[0][1].get('hostIPName')[0]
            HYPERVISOR = None
            if ccInfo[0][1].get('HYPERVISOR') != None:
                HYPERVISOR = ccInfo[0][1].get('HYPERVISOR')[0]
            clusterInfo = thd_ClusterInfo(clusterName=clusterName, hostIp=hostIp, HYPERVISOR=HYPERVISOR)
            ccList.append(clusterInfo)
    return  ccList

def p_get_clusterInfo_by_clusterIp(clusterIp):
    clusterInfo = None
    logger.info('p_get_clusterInfo_by_clusterIp(%s)' % (clusterIp))
    ldapip = g_ldap_ip
    username = g_user_name
    password = g_user_passwd    
    list_info = p_getClusterList(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'hostIPName=' + clusterIp)
    if(len(list_info) > 0):
        clusterInfo = list_info[0]
    return clusterInfo


def p_heart_beat_timer():
    global g_clc_ip
    global g_ldap_ip
    if g_clc_ip!=None:
        OpenLdap.p_all_heart_beat(g_clc_ip,g_ldap_ip,'ldap')
    heart = threading.Timer(1.0,p_heart_beat_timer)
    heart.start()

def p_get_global_ip():    
    global g_ldap_ip
    global g_user_name
    global g_user_passwd
    while True:
        g_ldap_ip,g_user_name,g_user_passwd = p_get_ldap_logoninfo()
        logger.info('g_ldap_ip:%s,g_user_name:%s,g_user_passwd:%s' %(g_ldap_ip,g_user_name,g_user_passwd))
        if  g_ldap_ip != None and g_user_name != None and g_user_passwd != None:
            break
        else:
            logger.info('ldap acquire ip error!!!')
            time.sleep(1)

def p_get_clusterinfo_by_cluster(clusterName):
    logger.info('p_get_clusterinfo_by_cluster()')
    clusterInfo = None
    if(clusterName == None):
        return None
    ldapip, username, password = p_get_ldap_info()
    list_info = []
    if(clusterName == 'any'):
        list_info = p_getClusterList(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'clusterName=*')
    else:
        list_info = p_getClusterList(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'clusterName=' + clusterName)
    if(len(list_info) > 0):
        clusterInfo = list_info[0]
    return clusterInfo


def p_getNodeList(ldapip, username, password, baseDN, searchFilter):
    nodeList = []
    ncRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    for ncInfo in ncRes:
        hostIp = None
        if ncInfo[0][1].get('IP') != None:
            hostIp = ncInfo[0][1].get('IP')[0]
        clusterName = None
        if ncInfo[0][1].get('pcc') != None:
            clusterName = ncInfo[0][1].get('pcc')[0]
        freeCPUs = 0
        if ncInfo[0][1].get('freeCPUs') != None:
            freeCPUs = string.atoi(ncInfo[0][1].get('freeCPUs')[0])
        freeDisk = 0
        if ncInfo[0][1].get('freeDisk') != None:
            freeDisk = string.atoi(ncInfo[0][1].get('freeDisk')[0])
        freeMem = 0
        if ncInfo[0][1].get('freeMem') != None:
            freeMem = string.atoi(ncInfo[0][1].get('freeMem')[0])
        totalCPUs = 0
        if ncInfo[0][1].get('totoalCPUs') != None:
            totalCPUs = string.atoi(ncInfo[0][1].get('totoalCPUs')[0])
        totalDisk = 0
        if ncInfo[0][1].get('totalDisk') != None:
            totalDisk = string.atoi(ncInfo[0][1].get('totalDisk')[0])
        totalMem = 0
        if ncInfo[0][1].get('totalMem') != None:
            totalMem = string.atoi(ncInfo[0][1].get('totalMem')[0])
        isLocal = False
        if ncInfo[0][1].get('dynamic') != None:    
            if ncInfo[0][1].get('dynamic')[0] == 'FALSE':
                isLocal = True
            
        nodeInfo = thd_NodeInfo(hostIp=hostIp,clusterName=clusterName,freeCPUs=freeCPUs,freeDisk=freeDisk,freeMem=freeMem,totalCPUs=totalCPUs,totalDisk=totalDisk,totalMem=totalMem)
        nodeInfo.isLocal=isLocal
        nodeList.append(nodeInfo)
    return nodeList


def p_getUserNameList(ldapip, username, password, baseDN, searchFilter):
    useNameList = []
    userRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for userInfo in userRes:
            userName = None
            if userInfo[0][1].get('UserNAME') != None:
                userName = userInfo[0][1].get('UserNAME')[0]
                useNameList.append(userName)
    return useNameList


def p_get_image_Infos(ldapip, username, password, baseDN, searchFilter):
    imageList = []
    imageRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(imageRes) > 0 and len(imageRes[0][0][1]) > 0:
        for img in imageRes:
            imageId = None
            if(img[0][1].get('imageId') != None):
                imageId = img[0][1].get('imageId')[0]
            imageLocation = None
            if(img[0][1].get('imageLocation') != None):
                imageLocation = img[0][1].get('imageLocation')[0]
            imageState = None
            if(img[0][1].get('imageState') != None):
                imageState = img[0][1].get('imageState')[0]
            imageOwnerId = None
            if (img[0][1].get('ownerid') != None):
                imageOwnerId = img[0][1].get('ownerid')[0]
            architecture = None
            if(img[0][1].get('architecture') != None):
                architecture = img[0][1].get('architecture')[0]
            HYPERVISOR = "kvm"
            if(img[0][1].get('HYPERVISOR') != None):
                HYPERVISOR = img[0][1].get('HYPERVISOR')[0]
            imageType = "desktop"
            if(img[0][1].get('ImageStyle') != None):
                imageType = img[0][1].get('ImageStyle')[0]
            isPublic = 0
            if img[0][1].get('public') != None:
                if img[0][1].get('public')[0] == 'TRUE' or img[0][1].get('public')[0] == 'true':
                    isPublic = 1
            signature = None
            if(img[0][1].get('signature') != None):
                signature = img[0][1].get('signature')[0]
            name = None
            if(img[0][1].get('name') != None):
                name = img[0][1].get('name')[0]
            imageCategory = 0
            if(img[0][1].get('imageCategory') != None):
                imageCategory = string.atoi(img[0][1].get('imageCategory')[0])
            description = None
            if  (img[0][1].get('description') != None):
                description = img[0][1].get('description')[0]
            platform = None
            if(img[0][1].get('platform') != None):
                platform = img[0][1].get('platform')[0]
            vmStyle = None
            if(img[0][1].get('vmStyle') != None):
                vmStyle = img[0][1].get('vmStyle')[0]
            createTime = None
            if(img[0][1].get('createTime') != None):
                createTime = img[0][1].get('createTime')[0]
            size = 0
            if(img[0][1].get('size') != None):
                size = string.atoi(img[0][1].get('size')[0])
            manifest = None
            if(img[0][1].get('manifest') != None):
                manifest = img[0][1].get('manifest')[0]
            imageInfo = thd_ImageInfo(\
                imageId=imageId,\
                imageLocation=imageLocation,\
                imageState=imageState,\
                imageOwnerId=imageOwnerId,\
                architecture=architecture,\
                imageType=imageType,\
                isPublic=isPublic,\
                signature=signature,\
                name=name,\
                imageCategory=imageCategory,\
                description=description, platform=platform,\
                vmStyle=vmStyle,\
                createTime=createTime,\
                size=size,\
                manifest=manifest,\
                HYPERVISOR=HYPERVISOR)
            imageList.append(imageInfo)
    return imageList


def p_get_all_image_list():
    ldapip, username, password = p_get_ldap_info()
    imageList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId=emi*')
    return imageList


def p_euca_get_domain_info(ldapip, username, password, baseDN, searchFilter):
    domainList = []
    domainres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    if len(domainres) > 0 and len(domainres[0][0][1]) > 0:
        for domaininfo in domainres:
            domainport = -1
            if(domaininfo[0][1].get('port') != None):
                domainport = int(domaininfo[0][1].get('port')[0])
            baseDN = None
            if(domaininfo[0][1].get('baseDN') != None):
                baseDN = domaininfo[0][1].get('baseDN')[0]
            domain = None
            if(domaininfo[0][1].get('domain') != None):
                domain = domaininfo[0][1].get('domain')[0]
            UserNAME = None
            if(domaininfo[0][1].get('UserNAME') != None):
                UserNAME = domaininfo[0][1].get('UserNAME')[0]
            encryptedPassword = None
            if(domaininfo[0][1].get('encryptedPassword') != None):
                encryptedPassword = domaininfo[0][1].get('encryptedPassword')[0]
            domainHost = None
            if(domaininfo[0][1].get('domainHost') != None):
                domainHost = domaininfo[0][1].get('domainHost')[0]
            domaineuca = thd_DomainInfo(domain=domain, domainHost=domainHost, UserNAME=UserNAME,\
                                        encryptedPassword=encryptedPassword, baseDN=baseDN, port=domainport)
            domainList.append(domaineuca)
    return domainList

def p_add_image_info(imageInfo):
    if imageInfo == None or imageInfo.imageId==None:
        return False 
    ret = False
    ldapip, username, password = p_get_ldap_info()
    imgList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId='+imageInfo.imageId)   
    if imgList==None or len(imgList)==0:
        newDN = 'imageId=' + imageInfo.imageId + ',' + IMAGE_BASEDN
        attrs = {}
        attrs['objectclass'] = ['IMG']
        attrs['imageId'] = imageInfo.imageId
        if imageInfo.name!=None:
            attrs['name'] = imageInfo.name
        if imageInfo.imageLocation!=None:
            attrs['imageLocation'] = imageInfo.imageLocation
        if imageInfo.imageState!=None:
            attrs['imageState'] = imageInfo.imageState 
        if imageInfo.imageOwnerId!=None:
            attrs['ownerid'] = imageInfo.imageOwnerId            
        if imageInfo.architecture!=None:
            attrs['architecture'] = imageInfo.architecture         
        if imageInfo.imageType!=None:
            attrs['ImageStyle'] = imageInfo.imageType 
        if imageInfo.platform!=None:
            attrs['platform'] = imageInfo.platform
            attrs['OS'] = imageInfo.platform                       
        if(imageInfo.isPublic!=None):
            if imageInfo.isPublic!=0:
                attrs['public'] = 'TRUE'
            else:
                attrs['public'] = 'FALSE'
        if imageInfo.imageCategory!=None:
            attrs['imageCategory'] = str(imageInfo.imageCategory)
        if imageInfo.description!=None:
            attrs['description'] = imageInfo.description
        else:
            attrs['description'] = ' '  #set default value
        if imageInfo.vmStyle!=None:
            attrs['vmStyle'] = imageInfo.vmStyle
        if imageInfo.createTime!=None:
            attrs['createTime'] = imageInfo.createTime
        if imageInfo.size!=None:
            attrs['size'] = str(imageInfo.size) 
        if imageInfo.HYPERVISOR!=None:
            attrs['HYPERVISOR'] = imageInfo.HYPERVISOR            
        logger.info('add image: %s' %str(attrs))   
        
        clc_ip = OpenLdap.get_clc_ip(ldapip)
        OpenLdap.p_addimg_update_global(clc_ip, imageInfo)
        ret = p_add_to_ldap(newDN, attrs)
    return ret    


def p_updateImageInfo(imageInfo):
    if imageInfo == None:
        return False
    ldapip, username, password = p_get_ldap_info()
    ncldap = p_login_ldap(ldapip, username, password)
    if ncldap == None:
        return False
    ret = False
    list_attr = []
    imageId = imageInfo.imageId
    if imageInfo.imageType != None:
        attr_imageType = (ldap.MOD_REPLACE, 'ImageStyle', imageInfo.imageType)
        list_attr.append(attr_imageType)
    if imageInfo.name != None:
        attr_name = (ldap.MOD_REPLACE, 'name', imageInfo.name)
        list_attr.append(attr_name)
    if imageInfo.imageCategory != None:
        attr_imageCategory = (ldap.MOD_REPLACE, 'imageCategory', str(imageInfo.imageCategory))
        list_attr.append(attr_imageCategory)
    if imageInfo.description != None:
        attr_description = (ldap.MOD_REPLACE, 'description', imageInfo.description)
        list_attr.append(attr_description)
    if imageInfo.platform != None:
        attr_platform = (ldap.MOD_REPLACE, 'platform', imageInfo.platform)
        list_attr.append(attr_platform)
    if imageInfo.createTime != None:
        attr_createTime = (ldap.MOD_REPLACE, 'createTime', imageInfo.createTime)
        list_attr.append(attr_createTime)
    if imageInfo.size != None:
        attr_size = (ldap.MOD_REPLACE, 'size', str(imageInfo.size))
        list_attr.append(attr_size)
    if imageInfo.HYPERVISOR != None:
        attr_HYPERVISOR = (ldap.MOD_REPLACE, 'HYPERVISOR', imageInfo.HYPERVISOR)
        list_attr.append(attr_HYPERVISOR)
    dn = 'imageId=%s,%s' % (imageId, IMAGE_BASE_DN)
    try:
        ncldap.modify_s(dn, list_attr)
        ret = True
    except ldap.LDAPError, e:
        logger.error('p_updateImageInfo:%s' % (e.message))
        ret = False
    ncldap.unbind_s()
    if ret:
        clc_ip = OpenLdap.get_clc_ip(ldapip)
        imgList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId=' + imageInfo.imageId)

        OpenLdap.p_updateimg_update_global(clc_ip, imgList[0])
    return ret

def p_deleteimage(imageID):
    if imageID == None:
        return False
    ldapip, username, password = p_get_ldap_info()
    ncldap = p_login_ldap(ldapip, username, password)
    if ncldap == None:
        return False
    ret = False
    dn = 'imageId=%s,%s' % (imageID, IMAGE_BASE_DN)
    try:
        ncldap.delete_s(dn)
        ret = True
    except ldap.LDAPError, e:
        logger.error('p_deleteimage:%s' % (e.message))
        ret = False
    ncldap.unbind_s()
    if ret:
        clc_ip = OpenLdap.get_clc_ip(ldapip)
        OpenLdap.p_delimg_update_global(clc_ip, imageID)
    return ret


def p_update_to_ldap(dn, list_attr):
    ldapip, username, password = p_get_ldap_info()
    ncldap = p_login_ldap(ldapip, username, password)
    if ncldap == None:
        return False
    try:
        ncldap.modify_s(dn, list_attr)
        ret = True
    except ldap.LDAPError, e:
        logger.error('p_update_to_ldap:%s' % (e.message))
        ret = False
    ncldap.unbind_s()
    return ret


def p_delete_to_ldap(dn):
    ldapip, username, password = p_get_ldap_info()
    ncldap = p_login_ldap(ldapip, username, password)
    if ncldap == None:
        return False
    try:
        ncldap.delete_s(dn)
        ret = True
    except ldap.LDAPError, e:
        logger.error('p_delete_to_ldap:%s' % (e.message))
        ret = False
    ncldap.unbind_s()
    return ret


def p_euca_is_user_exist(userName):
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    user = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'cn=' + userName, 'UserNAME')
    if(user == None):
        return False
    else:
        logger.info('user is: %s' % user)
        return True


def p_euca_is_department_exist(department):
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    depart = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, DEPARTMENT_BASEDN, 'cn=' + department, 'cn')
    if(depart == None):
        return False
    else:
        return True


def p_euca_add_department(department):       # ou=seriesname,cn=clc, o=cloudbot, o=sinobot      
    ret = False
    if(not p_euca_is_department_exist(department)):
        newDN = 'cn=' + department + ',' + DEPARTMENT_BASEDN
        attrs = {}
        attrs['objectclass'] = ['SRSNM']
        attrs['cn'] = department
        ret = p_add_to_ldap(newDN, attrs)
    return ret


def p_euca_is_admin(userName):
    ldapip, username, password = p_get_ldap_info()
    popedom = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn='+userName, 'popedom')
    logger.info('p_euca_is_admin popedom is:%s' %popedom )
    if (popedom == ADMIN_POPEDOM):
        return True
    else:
        return False


def p_euca_get_user_department_id(userName):
    departmentId = -1
    ldapip, username, password = p_get_ldap_info()
    department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'seriesID')
    if(department != None):
        departmentId = int(department)
    return departmentId


def p_get_department_by_user(userName):
    ldapip, username, password = p_get_ldap_info()
    department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'seriesNAME')
    return department


def p_euca_get_departmentId_by_department(depart):
    departId = -1
    ldapip, username, password = p_get_ldap_info()
    seriesRes = p_get_resultSet_from_ldap(ldapip, username, password, DEPARTMENT_BASEDN, 'cn=*', None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        id = 0
        for series in seriesRes:
            if(series[0][1].get('cn') != None):
                seriesName = series[0][1].get('cn')[0]
                if(seriesName == depart):
                    departId = id
                    break
            id = id + 1
    return  departId


def p_euca_get_department_by_id(departid):
    seriesName = None
    if(departid == None):
        seriesName = None
    if(departid == -1):
        seriesName = 'default'
    ldapip, username, password = p_get_ldap_info()
    seriesRes = p_get_resultSet_from_ldap(ldapip, username, password, DEPARTMENT_BASEDN, 'cn=*', None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        id = 0
        for series in seriesRes:
            if(departid == id):
                if(series[0][1].get('cn') != None):
                    seriesName = series[0][1].get('cn')[0]
                break
            id = id + 1
    return  seriesName


def p_euca_get_first_department():
    seriesName = None
    ldapip, username, password = p_get_ldap_info()
    seriesRes = p_get_resultSet_from_ldap(ldapip, username, password, DEPARTMENT_BASEDN, 'cn=*', None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        for series in seriesRes:
            if(series[0][1].get('cn') != None):
                seriesName = series[0][1].get('cn')[0]
                break
    return  seriesName


def p_euca_get_user_from_AD(domainHost, domainUser, password, baseDn, filter):
    res = p_get_resultSet_from_ldap(domainHost, domainUser, password, baseDn, filter, None)
    if(len(res) == 0):
        return None
    else:
        if len(res) > 0 and len(res[0][0][1]) > 0:
            userInfo = thd_UserInfo()
            for user in res:
                userInfo.seriesID = 0
                userInfo.sSeriesName = p_euca_get_first_department()
                if(user[0][1].get('cn') != None):
                    userInfo.userName = user[0][1].get('cn')[0]
                    userInfo.realName = user[0][1].get('cn')[0]
                    userInfo.sLogonName = user[0][1].get('cn')[0]
                    userInfo.confirmationCode = p_getDigestUrlBase64(user[0][1].get('cn')[0], 'sha512', False)
                if user[0][1].get('department') != None:
                    department = user[0][1].get('department')[0]
                    if(not p_euca_is_department_exist(department)):
                        p_euca_add_department(department)
                    userInfo.sSeriesName = department
                    userInfo.seriesID = p_euca_get_departmentId_by_department(department)
                if(user[0][1].get('accountExpires') != None):
                    userInfo.passwordExpires = int(user[0][1].get('accountExpires')[0])
            return userInfo
        else:
            return None


def p_getDigestUrlBase64(input, hash, isRandom):
    m = None
    if(hash == 'sha512'):
        m = hashlib.sha512()
    if(hash == 'sha224'):
        m = hashlib.sha224()
    if(hash == 'md5'):
        m = hashlib.md5()
    if(m != None):
        m.update(input)
        if(isRandom):
            input = input + str(int(time.time()))
            m.update(input)
        bstr = base64.urlsafe_b64encode(m.hexdigest())
        base64str = bstr.replace('=', 'A')
        return base64str
    return None


def p_euca_get_domain_info_from_ldap(domain):
    ldapip, username, password = p_get_ldap_info()
    domainlist = p_euca_get_domain_info(ldapip, username, password, PREFRENCE_BASEDN, 'cn=' + domain)
    if len(domainlist) > 0 :
        return domainlist[0]
    else:
        return None


def p_euca_add_user_info(userInfo):       # ou=zjut,o=cloudbot,o=sinobot      
    ret = False
#    if(cmp(userInfo.userName.lower(), 'administrator') == 0 or cmp(userInfo.userName.lower(), 'admin') == 0):
#        return ret
    if(not p_euca_is_user_exist(userInfo.userName)):
        newDN = 'cn=' + userInfo.userName + ',' + USER_INFO_BASEDN
        attrs = {}
        attrs['objectclass'] = ['person']
        attrs['objectclass'] = ['organizationalPerson']
        attrs['objectclass'] = ['inetOrgPerson']
        attrs['objectclass'] = ['cloudbotuser']
        attrs['sn'] = userInfo.realName
        attrs['realNAME'] = userInfo.realName
        if(userInfo.seriesID != None):
            attrs['seriesID'] = str(userInfo.seriesID)
        if(userInfo.sSeriesName != None):
            attrs['seriesNAME'] = userInfo.sSeriesName        
        attrs['UserNAME'] = userInfo.userName
        attrs['userPassword'] = userInfo.bCryptedPassword
        attrs['carLicense'] = userInfo.bCryptedPassword
        if userInfo.sLogonName!=None:
            attrs['displayName'] = userInfo.sLogonName
        if userInfo.email!=None:
            attrs['email'] = userInfo.email
        if(userInfo.isApproved):
            attrs['isApproved'] = 'TRUE'
        else:
            attrs['isApproved'] = 'FALSE'
        if(userInfo.isConfirmed):
            attrs['isConfirmed'] = 'TRUE'
        else:
            attrs['isConfirmed'] = 'FALSE'
        if(userInfo.isEnabled):
            attrs['isEnable'] = 'TRUE'
        else:
            attrs['isEnable'] = 'FALSE'
        if(userInfo.isPrivateImgCreated):
            attrs['isPrivateImgCreated'] = 'TRUE'
        else:
            attrs['isPrivateImgCreated'] = 'FALSE'
        if userInfo.maxPrivateInstances!=None:
            attrs['MaxPrivateInstances'] = str(userInfo.maxPrivateInstances)    
        attrs['popedom'] = str(userInfo.popedom)
        attrs['passwordExpires'] = str(userInfo.passwordExpires)
        attrs['uid'] = str(userInfo.reservationId)
        attrs['confirmetionCode'] = userInfo.confirmationCode
        attrs['certificateCode'] = userInfo.certificateCode
        if(userInfo.domain!=None):
            attrs['domain'] = userInfo.domain
        ret = p_add_to_ldap(newDN, attrs)
    return ret


def p_euca_add_auth_user(userInfo):       # ou=auth_info,ou=auth_user,o=cloudbot,o=sinobot 
    ret = False
    newDN = 'uuid=' + str(uuid.uuid4()) + ',' + AUTH_INFO_BASEDN
    attrs = {}
    attrs['objectclass'] = ['AUTHINFO']
    if(userInfo.isEnabled):
        attrs['isEnable'] = 'TRUE'
    else:
        attrs['isEnable'] = "FALSE"
    if(userInfo.isAdministrator):
        attrs['isAdministrator'] = 'TRUE'
    else:
        attrs['isAdministrator'] = "FALSE"
    attrs['queryId'] = p_getDigestUrlBase64(userInfo.userName, 'sha224', False)
    attrs['secretKey'] = p_getDigestUrlBase64(userInfo.userName, 'sha224', True)
    attrs['UserNAME'] = userInfo.userName
    ret = p_add_to_ldap(newDN, attrs)
    return ret


def p_euca_get_images_by_user(userName):
    imageInfos = []
    ldapip, username, password = p_get_ldap_info()
    imageList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId=emi*')
    departmentId = p_euca_get_user_department_id(userName)
    if(p_euca_is_admin(userName)):
        return imageList
    else:
        if(len(imageList) > 0):
            for image in imageList:
                imageCategory = image.imageCategory
                if((imageCategory == 1) or (imageCategory == 0 and image.imageOwnerId == userName ) or (
                departmentId == (imageCategory - 1000))):
                    imageInfos.append(image)
    return imageInfos


def get_container_by_department(department):
    if(department == None):
        return None
    ldapip, username, password = p_get_ldap_info()
    container = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=' + department, 'ou')
    return container


def get_container_count():
    ldapip, username, password = p_get_ldap_info()
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    return len(res)


def p_get_vmconfig_from_res(coninfo):
    if(coninfo == None):
        return None
    vmConfig = thd_vmConfig()
    vmConfig.id = coninfo[0][1].get('cn')[0]
    if(coninfo[0][1].get('UserNAME') != None ):
        vmConfig.user = coninfo[0][1].get('UserNAME')[0]
    if(coninfo[0][1].get('imageId') != None ):
        vmConfig.image_id = coninfo[0][1].get('imageId')[0]
    if(coninfo[0][1].get('isAssignNode') != None ):
        if(cmp(coninfo[0][1].get('isAssignNode')[0].lower(), 'true') == 0 ):
            vmConfig.is_assign_node = True
        else:
            vmConfig.is_assign_node = False
    if(coninfo[0][1].get('nodeIp') != None ):
        vmConfig.node_ip = coninfo[0][1].get('nodeIp')[0]
            
    netInfo = thd_net_info()
    if(coninfo[0][1].get('domain') != None):
        netInfo.domain = coninfo[0][1].get('domain')[0]
    if(coninfo[0][1].get('publicIp') != None ):
        netInfo.public_ip = coninfo[0][1].get('publicIp')[0]
    if(coninfo[0][1].get('publicMac') != None):
        netInfo.public_mac = coninfo[0][1].get('publicMac')[0]
    if(coninfo[0][1].get('gateway') != None):
        netInfo.gateway = coninfo[0][1].get('gateway')[0]    
    if(coninfo[0][1].get('netmask') != None):
        netInfo.netmask = coninfo[0][1].get('netmask')[0]
    if(coninfo[0][1].get('dnsDomain') != None):
        netInfo.dns = coninfo[0][1].get('dnsDomain')[0]
    if(coninfo[0][1].get('wins') != None):
        netInfo.wins = coninfo[0][1].get('wins')[0]
    if(coninfo[0][1].get('netMode') != None):
            netInfo.net_mode = coninfo[0][1].get('netMode')[0]    
    if(coninfo[0][1].get('isDHCP') != None ):
        if( cmp(coninfo[0][1].get('isDHCP')[0].lower(), 'true') == 0):
            netInfo.ip_dhcp = True
        else:
            netInfo.ip_dhcp = False    
    vmConfig.net_info = netInfo
    
    vmInfo = thd_vm_info()
    if(coninfo[0][1].get('vmcpuNum') != None):
        vmInfo.vm_cpu = int(coninfo[0][1].get('vmcpuNum')[0])
    if(coninfo[0][1].get('vmdisk') != None):
        vmInfo.vm_disk = int(coninfo[0][1].get('vmdisk')[0])
    if(coninfo[0][1].get('vmmemory') != None):
        vmInfo.vm_memory = int(coninfo[0][1].get('vmmemory')[0])
    if(coninfo[0][1].get('machinename') != None):
        vmInfo.machine_name = coninfo[0][1].get('machinename')[0] 
    if(coninfo[0][1].get('isClearPowerOff') != None ):
        if( cmp(coninfo[0][1].get('isClearPowerOff')[0].lower(), 'true') == 0):
            vmInfo.is_clear_power_off = True
        else:
            vmInfo.is_clear_power_off  = False
    vmConfig.vm_info = vmInfo    
    
    thermophoresis = thd_thermophoresis()
    if(coninfo[0][1].get('thermophoresisNode') != None):
        thermophoresis.thermophoresis_node = coninfo[0][1].get('thermophoresisNode')[0]
    if(coninfo[0][1].get('isThermophoresis') != None ):
        if( cmp(coninfo[0][1].get('isThermophoresis')[0].lower(), 'true') == 0):
            thermophoresis.is_thermophoresis = True
        else:
            thermophoresis.is_thermophoresis = False
    vmConfig.thermophoresis = thermophoresis
    
    snapshot = thd_support_snapshot()        
    if(coninfo[0][1].get('isSnapshot') != None ):
        if( cmp(coninfo[0][1].get('isSnapshot')[0].lower(), 'true') == 0):
            snapshot.is_snapshot = True
        else:
            snapshot.is_snapshot = False
    if(coninfo[0][1].get('maxSnapshot') != None):
        snapshot.max_snapshot = int(coninfo[0][1].get('maxSnapshot')[0])
    vmConfig.snapshot = snapshot
    
    peripheral = thd_peripheral()    
    if(coninfo[0][1].get('isSupportUsb') != None ):
        if( cmp(coninfo[0][1].get('isSupportUsb')[0].lower(), 'true') == 0):
            peripheral.is_support_usb = True
        else:
            peripheral.is_support_usb = False
    if(coninfo[0][1].get('maxUsbNum') != None ):
        peripheral.max_usb_number = int(coninfo[0][1].get('maxUsbNum')[0])
    if(coninfo[0][1].get('isSupportParallel') != None ):
        if( cmp(coninfo[0][1].get('isSupportParallel')[0].lower(), 'true') == 0):
            peripheral.is_support_parallel = True
        else:
            peripheral.is_support_parallel = False
    if(coninfo[0][1].get('isSupportPeripheral') != None ):
        if( cmp(coninfo[0][1].get('isSupportPeripheral')[0].lower(), 'true') == 0):
            peripheral.is_support_peripheral = True
        else:
            peripheral.is_pupport_peripheral = False
    if(coninfo[0][1].get('isExtDisk') != None ):
        if( cmp(coninfo[0][1].get('isExtDisk')[0].lower(), 'true') == 0):
            peripheral.is_external_device = True
        else:
            peripheral.is_external_device = False    
    if(coninfo[0][1].get('extDisk') != None):
        peripheral.external_disk = int(coninfo[0][1].get('extDisk')[0])    
    vmConfig.peripheral = peripheral    
    return vmConfig

def p_euca_get_vmconfig_by_usrimg(preVmConfig):
    vmConfig = None
    logger.info('p_euca_get_vmconfig_by_usrimg:user: %s ' % preVmConfig.user)
    ldapip, username, password = p_get_ldap_info()
    department = None
    container = None
    if preVmConfig.user_department_id!=-1:
        department = p_euca_get_department_by_id(preVmConfig.user_department_id)
        if(department != None):
            container = get_container_by_department(department)
        if(container == None):
            container = 'default'
    else:
        container = 'default'
    baseDN = 'ou=' + container + ',' + VM_CONFIG_BASEDN
    res = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=*', None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for coninfo in res:
            if(coninfo[0][1].get('imageId') != None and coninfo[0][1].get('imageId')[0] == preVmConfig.image_id ) and ( coninfo[0][1].get('UserNAME') != None and coninfo[0][1].get('UserNAME')[0] == preVmConfig.user ) and (coninfo[0][1].get('nodeIp') != None and coninfo[0][1].get('nodeIp')[0] == preVmConfig.node_ip ) :
                vmConfig = p_get_vmconfig_from_res(coninfo)
                if(container == 'default'):
                    vmConfig.user_department_id = -1
                else:
                    vmConfig.user_department_id =p_euca_get_departmentId_by_department(department)
                break
    return vmConfig

def p_euca_get_vmconfig(preVmConfig):
    if not preVmConfig.is_assign_node:
        preVmConfig.node_ip='any'    
    vmConfig = p_euca_get_vmconfig_by_usrimg(preVmConfig)
    return vmConfig


def p_get_vmconfigs_by_user(userName):
    vms = []
    vmcfgList = p_get_all_vmconfig()
    logger.info('p_get_vmconfigs_by_user user is %s:' % userName)
    if p_euca_is_admin(userName):
        return vmcfgList
    if(len(vmcfgList) > 0):
        for vm in vmcfgList:
            if(vm.user == userName):
                vms.append(vm)    
    return vms


def p_get_all_vmconfig():
    vmcfgList = []
    ldapip, username, password = p_get_ldap_info()
    
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for contain in res:
            if contain[0][1].get('ou') != None:
                conname = contain[0][1].get('ou')[0]
                baseDN = 'ou=' + conname + ',' + VM_CONFIG_BASEDN
                configres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=*', None)
                if len(configres) > 0 and len(configres[0][0][1]) > 0:
                    for configinfo in configres:
                        vmConfig = p_get_vmconfig_from_res(configinfo)
                        if(contain == 'default'):
                            vmConfig.user_department_id = -1
                        else:
                            department = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN,'ou=' + conname, 'hostname')
                            vmConfig.user_department_id = p_euca_get_departmentId_by_department(department)
                        vmcfgList.append(vmConfig)
    return vmcfgList


def p_get_vmconfig_by_id(id):
    vmConfig = None
    ldapip, username, password = p_get_ldap_info()
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    containList = []
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for contain in res:
            if contain[0][1].get('ou') != None:
                strcontain = contain[0][1].get('ou')[0]
                baseDN = 'ou=' + strcontain + ',' + VM_CONFIG_BASEDN
                configres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=' + id, None)
                if len(configres) > 0 and len(configres[0][0][1]) > 0:
                    vmConfig = p_get_vmconfig_from_res(configres[0])
                    if(contain == 'default'):
                        vmConfig.user_department_id = -1
                    else:
                        vmConfig.user_department_id = p_euca_get_departmentId_by_department(contain[0][1].get('hostname')[0])
                    break
    return  vmConfig


def p_get_vmconfig_by_node(nodeIp):
    vmConfigList = []
    vmcfgList = p_get_all_vmconfig()
    if nodeIp == None or cmp(nodeIp.lower(), ALL_MEAN) == 0:
        return vmcfgList
    if(len(vmcfgList) > 0):
        for vmconfig in vmcfgList:
            if (vmconfig.node_ip == nodeIp ):
                vmConfigList.append(vmconfig)
    return vmConfigList


def p_get_vmconfig_by_cluster(clusterName):
    vmConfigList = []
    ldapip, username, password = p_get_ldap_info()
    vmcfgList = p_get_all_vmconfig()
    if(clusterName == 'None' or cmp(clusterName.lower(), ALL_MEAN) == 0):
        return vmcfgList
    nodelist = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'pcc=' + clusterName)
    for vmconfig in vmcfgList:
        for nodeInfo in nodelist:
            if (vmconfig.node_ip == nodeInfo.hostIp ):
                vmConfigList.append(vmconfig)
    return vmConfigList


def p_add_default_container():
    ret = True
    container = 'default'
    ldapip, username, password = p_get_ldap_info()
    strou = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'ou=' + container, 'ou')
    if(strou == None):
        newConDN = 'ou=' + container + ',' + VM_CONFIG_BASEDN
        attrsCon = {}
        attrsCon['objectClass'] = 'EUCACONTAINER'
        attrsCon['hostname'] = 'default'
        ret = p_add_to_ldap(newConDN, attrsCon)
    return ret    


class addvm_update_clc_thread(threading.Thread):
    def __init__(self,clc_ip, vmconfig):
        threading.Thread.__init__(self)
        self.clc_ip = clc_ip
        self.vmconfig = vmconfig

    def run(self):
        is_sucess = False
        while not is_sucess:
            is_sucess=OpenLdap.p_addvm_update_global(self.clc_ip, self.vmconfig)
            if not is_sucess:
                logger.error("update clc global p_addvm_update_global:%s is error !" %str(self.vmconfig)) 
            time.sleep(DEFAULT_DELAY)
        logger.warn("addvm_update_clc_thread :%s sucess!" %str(self.vmconfig))

class updatevm_update_clc_thread(threading.Thread):
    def __init__(self,clc_ip, vmconfig):
        threading.Thread.__init__(self)
        self.clc_ip = clc_ip
        self.vmconfig = vmconfig

    def run(self):
        is_sucess = False
        while not is_sucess:
            is_sucess=OpenLdap.p_updatevm_update_global(self.clc_ip, self.vmconfig)
            if not is_sucess:
                logger.error("update clc global p_updatevm_update_global:%s is error !" %str(self.vmconfig))           
            time.sleep(DEFAULT_DELAY)
        logger.warn("updatevm_update_clc_thread :%s sucess!" %str(self.vmconfig))

def p_add_vmconfig_to_ldap(vmConfig):
    logger.debug('add the vmconfig: %s' %str(vmConfig))
    ret = True
    container = None
    ldapip, username, password = p_get_ldap_info()
    department = None
    # the department container
    if vmConfig.user_department_id != -1:
        department = p_euca_get_department_by_id(vmConfig.user_department_id)
        if(department != None):
            container = get_container_by_department(department)
            if(container == None):
                m = hashlib.md5()
                m.update(department)
                container = m.hexdigest()
                newConDN = 'ou=' + container + ',' + VM_CONFIG_BASEDN
                attrsCon = {}
                attrsCon['objectClass'] = 'EUCACONTAINER'
                attrsCon['hostname'] = department
                ret = p_add_to_ldap(newConDN, attrsCon)
        else:
            ret = False    
    else:
        container = 'default'
        ret = p_add_default_container()
 
    #add vmconfig to ldap
    if ret:
        attrs = {}
        cn = str(uuid.uuid4())
        attrs['objectClass'] = 'VMCONFIG'
        attrs['cn'] = cn
        attrs['UserNAME'] = vmConfig.user
        attrs['imageId'] = vmConfig.image_id       
        if(vmConfig.is_assign_node != None):
            if(vmConfig.is_assign_node):
                attrs['isAssignNode'] = 'TRUE'
                attrs['nodeIp'] = vmConfig.node_ip                
            else:
                attrs['isAssignNode'] = 'FALSE'
                attrs['nodeIp'] = 'any'
                    
        if vmConfig.net_info!=None :
            if vmConfig.net_info.domain != None:
                attrs['domain'] = vmConfig.net_info.domain
            if vmConfig.net_info.public_ip != None:
                attrs['publicIp'] = vmConfig.net_info.public_ip
            if(vmConfig.net_info.public_mac != None):
                attrs['publicMac'] = vmConfig.net_info.public_mac
            if(vmConfig.net_info.gateway != None):
                attrs['gateway'] = vmConfig.net_info.gateway
            if(vmConfig.net_info.net_mode != None):
                attrs['netMode'] = vmConfig.net_info.net_mode
            if(vmConfig.net_info.netmask != None):
                attrs['netmask'] = vmConfig.net_info.netmask
            if(vmConfig.net_info.dns != None):
                attrs['dnsDomain'] = vmConfig.net_info.dns
            if(vmConfig.net_info.wins != None):
                attrs['wins'] = vmConfig.net_info.wins
            if(vmConfig.net_info.ip_dhcp != None):
                if(vmConfig.net_info.ip_dhcp):
                    attrs['isDHCP'] = 'TRUE'
                else:
                    attrs['isDHCP'] = 'FALSE'        
            
        if vmConfig.vm_info!=None:
            if(vmConfig.vm_info.machine_name != None):
                attrs['machinename'] = vmConfig.vm_info.machine_name         
            if(vmConfig.vm_info.vm_cpu != None):
                attrs['vmcpuNum'] = str(vmConfig.vm_info.vm_cpu)
            if(vmConfig.vm_info.vm_memory != None):
                attrs['vmmemory'] = str(vmConfig.vm_info.vm_memory)
            if(vmConfig.vm_info.vm_disk != None):
                attrs['vmdisk'] = str(vmConfig.vm_info.vm_disk)
            if(vmConfig.vm_info.is_clear_power_off!=None):
                if vmConfig.vm_info.is_clear_power_off:
                    attrs['isClearPowerOff'] = 'TRUE'
                else:
                    attrs['isClearPowerOff'] = 'FALSE'
            else:
                attrs['isClearPowerOff'] = 'FALSE'

        if vmConfig.thermophoresis!=None :
            if(vmConfig.thermophoresis.is_thermophoresis != None):
                if(vmConfig.thermophoresis.is_thermophoresis):
                    attrs['isThermophoresis'] = 'TRUE'
                else:
                    attrs['isThermophoresis'] = 'FALSE'
            if(vmConfig.thermophoresis.thermophoresis_node != None):
                attrs['thermophoresisNode'] = vmConfig.thermophoresis.thermophoresis_node                
        
        if vmConfig.snapshot!=None:           
            if(vmConfig.snapshot.is_snapshot != None):
                if(vmConfig.snapshot.is_snapshot):
                    attrs['isSnapshot'] = 'TRUE'
                else:
                    attrs['isSnapshot'] = 'FALSE'
            if(vmConfig.snapshot.max_snapshot != None):
                attrs['maxSnapshot'] = str(vmConfig.snapshot.max_snapshot)
        
        if vmConfig.peripheral!=None:
            if(vmConfig.peripheral.is_external_device != None):
                if(vmConfig.peripheral.is_external_device):
                    attrs['isExtDisk'] = 'TRUE'
                else:
                    attrs['isExtDisk'] = 'FALSE'
            if(vmConfig.peripheral.external_disk != None):
                attrs['extDisk'] = str(vmConfig.peripheral.external_disk)                
            if(vmConfig.peripheral.is_support_usb != None):
                if(vmConfig.peripheral.is_support_usb):
                    attrs['isSupportUsb'] = 'TRUE'
                else:
                    attrs['isSupportUsb'] = 'FALSE'
            if(vmConfig.peripheral.max_usb_number != None):
                    attrs['maxUsbNum'] = str(vmConfig.peripheral.max_usb_number)        
            if(vmConfig.peripheral.is_support_parallel != None):
                if(vmConfig.peripheral.is_support_parallel):
                    attrs['isSupportParallel'] = 'TRUE'
                else:
                    attrs['isSupportParallel'] = 'FALSE'        
            if(vmConfig.peripheral.is_support_peripheral != None):
                if(vmConfig.peripheral.is_support_peripheral):
                    attrs['isSupportPeripheral'] = 'TRUE'
                else:
                    attrs['isSupportPeripheral'] = 'FALSE'

        newDN = 'cn=' + cn + ',ou=' + container + ',' + VM_CONFIG_BASEDN
        ret = p_add_to_ldap(newDN, attrs)
        if ret:
            clc_ip = OpenLdap.get_clc_ip(ldapip)
            vmConfig.id = cn
            addvm_thread = addvm_update_clc_thread(clc_ip,vmConfig)  # update clc global 
            addvm_thread.start()
    return ret


def p_update_vmconfig_info(vmConfig):
    department = None
    ldapip, username, password = p_get_ldap_info()
    container = None
    logger.info('p_update_vmconfig_info vmConfig.user:%s' % str(vmConfig))
    if(vmConfig.user_department_id != None):
        if(vmConfig.user_department_id != -1):
            department = p_euca_get_department_by_id(vmConfig.user_department_id)
        else:
            department = 'default'
        if(department != None):
            container = get_container_by_department(department)
        if(container == None):
            container = 'default'
    else:
        return False

    if (container == 'default'):
        p_add_default_container()

    dn = 'cn=' + vmConfig.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN

    logger.info('p_update_vmconfig_info vmConfig.user:%s' % dn)
    list_attr = []
    if(vmConfig.user != None):
        attr = (ldap.MOD_REPLACE, 'UserNAME', None)
        if(len(vmConfig.user) > 0):
            attr = (ldap.MOD_REPLACE, 'UserNAME', vmConfig.user)
        list_attr.append(attr)
    if(vmConfig.image_id != None):
        attr = (ldap.MOD_REPLACE, 'imageId', None)
        if(len(vmConfig.image_id) > 0):
            attr = (ldap.MOD_REPLACE, 'imageId', vmConfig.image_id)
        list_attr.append(attr)                    
    
    if vmConfig.net_info!=None:
        if(vmConfig.net_info.domain != None):
            attr = (ldap.MOD_REPLACE, 'domain', None)
            if(len(vmConfig.net_info.domain) > 0):
                attr = (ldap.MOD_REPLACE, 'domain', vmConfig.net_info.domain)
            list_attr.append(attr)    
        if(vmConfig.net_info.public_ip != None):
            attr = (ldap.MOD_REPLACE, 'publicIp', None)
            if(len(vmConfig.net_info.public_ip) > 0):
                attr = (ldap.MOD_REPLACE, 'publicIp', vmConfig.net_info.public_ip)
            list_attr.append(attr)
        if(vmConfig.net_info.public_mac != None):
            attr = (ldap.MOD_REPLACE, 'publicMac', None)
            if(len(vmConfig.net_info.public_mac) > 0):
                attr = (ldap.MOD_REPLACE, 'publicMac', vmConfig.net_info.public_mac)
            list_attr.append(attr)
        if(vmConfig.net_info.gateway != None):
            attr = (ldap.MOD_REPLACE, 'gateway', None)
            if(len(vmConfig.net_info.gateway) > 0):
                attr = (ldap.MOD_REPLACE, 'gateway', vmConfig.net_info.gateway)
            list_attr.append(attr)
        if(vmConfig.net_info.net_mode != None):
            attr = (ldap.MOD_REPLACE, 'netMode', None)
            if(len(vmConfig.net_info.net_mode) > 0):
                attr = (ldap.MOD_REPLACE, 'netMode', vmConfig.net_info.net_mode)
            list_attr.append(attr)
        if(vmConfig.net_info.netmask != None):
            attr = (ldap.MOD_REPLACE, 'netmask', None)
            if(len(vmConfig.net_info.netmask) > 0):
                attr = (ldap.MOD_REPLACE, 'netmask', vmConfig.net_info.netmask)
            list_attr.append(attr)
        if(vmConfig.net_info.dns != None):
            attr = (ldap.MOD_REPLACE, 'dnsDomain', None)
            if(len(vmConfig.net_info.dns) > 0):
                attr = (ldap.MOD_REPLACE, 'dnsDomain', vmConfig.net_info.dns)
            list_attr.append(attr)
        if(vmConfig.net_info.wins != None):
            attr = (ldap.MOD_REPLACE, 'wins', None)
            if(len(vmConfig.net_info.wins) > 0):
                attr = (ldap.MOD_REPLACE, 'wins', vmConfig.net_info.wins)
            list_attr.append(attr)    
        if(vmConfig.net_info.ip_dhcp != None):
            attr = None
            if(vmConfig.net_info.ip_dhcp):
                attr = (ldap.MOD_REPLACE, 'isDHCP', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isDHCP', 'FALSE')
        list_attr.append(attr)    

    if vmConfig.vm_info!=None:
        if(vmConfig.vm_info.machine_name != None):
            attr = (ldap.MOD_REPLACE, 'machinename', None)
            if(len(vmConfig.vm_info.machine_name) > 0):
                attr = (ldap.MOD_REPLACE, 'machinename', vmConfig.vm_info.machine_name)
            list_attr.append(attr)        
        if(vmConfig.vm_info.vm_cpu != None):
            attr = (ldap.MOD_REPLACE, 'vmcpuNum', str(vmConfig.vm_info.vm_cpu))
            list_attr.append(attr)
        if(vmConfig.vm_info.vm_memory != None):
            attr = (ldap.MOD_REPLACE, 'vmmemory', str(vmConfig.vm_info.vm_memory))
            list_attr.append(attr)
        if(vmConfig.vm_info.vm_disk != None):
            attr = (ldap.MOD_REPLACE, 'vmdisk', str(vmConfig.vm_info.vm_disk))
            list_attr.append(attr)    
    
    if vmConfig.thermophoresis!=None:    
        if(vmConfig.thermophoresis.is_thermophoresis != None):
            attr = None
            if(vmConfig.thermophoresis.is_thermophoresis):
                attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'FALSE')
            list_attr.append(attr)
        if(vmConfig.thermophoresis.thermophoresis_node != None):
            attr = (ldap.MOD_REPLACE, 'thermophoresisNode', None)
            if(len(vmConfig.thermophoresis.thermophoresis_node) > 0):
                attr = (ldap.MOD_REPLACE, 'thermophoresisNode', vmConfig.thermophoresis.thermophoresis_node)
            list_attr.append(attr)
    
    if vmConfig.snapshot!=None:    
        if(vmConfig.snapshot.is_snapshot != None):
            attr = None
            if(vmConfig.snapshot.is_snapshot):
                attr = (ldap.MOD_REPLACE, 'isSnapshot', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isSnapshot', 'FALSE')
            list_attr.append(attr)
        if(vmConfig.snapshot.max_snapshot != None):
            attr = (ldap.MOD_REPLACE, 'maxSnapshot', str(vmConfig.snapshot.max_snapshot))
            list_attr.append(attr)
    
    if vmConfig.peripheral!=None:
        if(vmConfig.peripheral.is_external_device != None):
            attr = None
            if(vmConfig.peripheral.is_external_device):
                attr = (ldap.MOD_REPLACE, 'isExtDisk', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isExtDisk', 'FALSE')
            list_attr.append(attr)
        if(vmConfig.peripheral.external_disk != None):
            attr = (ldap.MOD_REPLACE, 'extDisk', str(vmConfig.peripheral.external_disk))
            list_attr.append(attr)                                
        if(vmConfig.peripheral.is_support_peripheral != None):
            attr = None
            if(vmConfig.peripheral.is_support_peripheral):
                attr = (ldap.MOD_REPLACE, 'isSupportPeripheral', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isSupportPeripheral', 'FALSE')
            list_attr.append(attr)        
        if(vmConfig.peripheral.is_support_usb != None):
            attr = None
            if(vmConfig.peripheral.is_support_usb):
                attr = (ldap.MOD_REPLACE, 'isSupportUsb', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isSupportUsb', 'FALSE')
            list_attr.append(attr)
        if(vmConfig.peripheral.max_usb_number != None):
            attr = (ldap.MOD_REPLACE, 'maxUsbNum', str(vmConfig.peripheral.max_usb_number))
            list_attr.append(attr)        
        if(vmConfig.peripheral.is_support_parallel != None):
            attr = None
            if(vmConfig.peripheral.is_support_parallel):
                attr = (ldap.MOD_REPLACE, 'isSupportParallel', 'TRUE')
            else:
                attr = (ldap.MOD_REPLACE, 'isSupportParallel', 'FALSE')
            list_attr.append(attr)
    
    ret = p_update_to_ldap(dn, list_attr)
    if ret:
        clc_ip = OpenLdap.get_clc_ip(ldapip)
        updatevm_thread = updatevm_update_clc_thread(clc_ip,vmConfig)  # update clc global 
        updatevm_thread.start()
    return ret

# change vmconfig : the no change item use old value at ldap
def p_convert_to_new_vmconfig(oldConfig, vmConfig):
    if(vmConfig.user_department_id != None):
        oldConfig.user_department_id = vmConfig.user_department_id
    if(vmConfig.user != None):
        oldConfig.user = vmConfig.user
    if(vmConfig.image_id != None):
        oldConfig.image_id = vmConfig.image_id        
    
    if vmConfig.net_info!=None:
        netInfo = thd_net_info()
        if(vmConfig.net_info.domain != None):
            netInfo.domain = vmConfig.net_info.domain                    
        if(vmConfig.net_info.public_ip != None):
            netInfo.public_ip = vmConfig.net_info.public_ip
        if(vmConfig.net_info.public_mac != None):
            netInfo.public_mac = vmConfig.net_info.public_mac
        if(vmConfig.net_info.gateway != None):
            netInfo.gateway = vmConfig.net_info.gateway
        if(vmConfig.net_info.net_mode != None):
            netInfo.net_mode = vmConfig.net_info.net_mode
        if(vmConfig.net_info.netmask != None):
            netInfo.netmask = vmConfig.net_info.netmask
        if(vmConfig.net_info.dns != None):
            netInfo.dns = vmConfig.net_info.dns
        if(vmConfig.net_info.wins != None):
            netInfo.wins = vmConfig.net_info.wins
        if(vmConfig.net_info.ip_dhcp != None):
            netInfo.ip_dhcp = vmConfig.net_info.ip_dhcp        
        logger.debug('net info: %s' %str(netInfo))
        oldConfig.net_info = netInfo
        logger.debug('nnew vmconfig: %s' %str(oldConfig))
    
    if vmConfig.vm_info!=None:
        vmInfo = thd_vm_info()
        if(vmConfig.vm_info.machine_name != None):
            vmInfo.machine_name = vmConfig.vm_info.machine_name                
        if(vmConfig.vm_info.vm_cpu != None):
            vmInfo.vm_cpu = vmConfig.vm_info.vm_cpu
        if(vmConfig.vm_info.vm_memory != None):
            vmInfo.vm_memory = vmConfig.vm_info.vm_memory
        if(vmConfig.vm_info.vm_disk != None):
            vmInfo.vm_disk = vmConfig.vm_info.vm_disk
        oldConfig.vm_info = vmInfo        
    
    if vmConfig.thermophoresis!=None:
        thermophoresis = thd_thermophoresis()    
        if(vmConfig.thermophoresis.is_thermophoresis != None):
            thermophoresis.is_thermophoresis = vmConfig.thermophoresis.is_thermophoresis
        if(vmConfig.thermophoresis.thermophoresis_node != None):
            thermophoresis.thermophoresis_node = vmConfig.thermophoresis.thermophoresis_node
        oldConfig.thermophoresis = thermophoresis
                
    if vmConfig.snapshot!=None:
        snapshot = thd_support_snapshot()
        if(vmConfig.snapshot.is_snapshot != None):
            snapshot.is_snapshot = vmConfig.snapshot.is_snapshot
        if(vmConfig.snapshot.max_snapshot != None):
            snapshot.max_snapshot = vmConfig.snapshot.max_snapshot
        oldConfig.snapshot = snapshot
        
    if vmConfig.peripheral!=None:
        peripheral = thd_peripheral()
        if(vmConfig.peripheral.is_external_device != None):
            peripheral.is_external_device = vmConfig.peripheral.is_external_device
        if(vmConfig.peripheral.external_disk != None):
            peripheral.external_disk = vmConfig.peripheral.external_disk                        
        if(vmConfig.peripheral.is_support_usb != None):
            peripheral.is_support_usb = vmConfig.peripheral.is_support_usb
        if(vmConfig.peripheral.max_usb_number != None):
            peripheral.max_usb_number = vmConfig.peripheral.max_usb_number        
        if(vmConfig.peripheral.is_support_parallel != None):
            peripheral.is_support_parallel = vmConfig.peripheral.is_support_parallel
        if(vmConfig.peripheral.is_support_peripheral != None):
            peripheral.is_support_peripheral = vmConfig.peripheral.is_support_peripheral
        oldConfig.peripheral = peripheral    
    return oldConfig


def p_change_vmconfig_to_ldap(vmConfig):
    ret = False
    if(vmConfig.id == None):
        return ret
    vm = p_get_vmconfig_by_id(vmConfig.id)
    if(vm == None):
        return ret
    logger.info('p_change_vmconfig_to_ldap vmConfig.id:%s' % str(vm))
    if(vm.user == vmConfig.user or vmConfig.user == None):
        newVmconfig = p_convert_to_new_vmconfig(vm, vmConfig)
        logger.info('p_change_vmconfig_to_ldap update vmconfig:%s' % str(newVmconfig))
        ret = p_update_vmconfig_info(newVmconfig)
    else:
        ret = p_delete_vmconfig_from_ldap(vm)
        if(ret):
            newVmconfig = p_convert_to_new_vmconfig(vm, vmConfig)
            p_add_vmconfig(newVmconfig)
    return ret


def p_delete_vmconfig_by_node(nodeIp):
    vmList = []
    if(nodeIp == None or cmp(nodeIp.lower(), 'all') == 0):
        vmList = p_get_all_vmconfig()
    else:
        vmList = p_get_vmconfig_by_node(nodeIp)
    if(len(vmList) > 0):
        for vm in vmList:
            container = None
            if(vm.user_department_id == None):
                if(vm.user == None or vm.user == 'any'):
                    container = 'default'
                else:
                    department = p_get_department_by_user(vm.user)
                    if(department == None):
                        container = 'default'
                    else:
                        container = get_container_by_department(department)
            else:
                if(vm.user_department_id == -1):
                    container = 'default'
                else:
                    department = p_euca_get_department_by_id(vm.user_department_id)
                    container = get_container_by_department(department)
            if(container == None):
                continue

            ldap_ip =  utility.get_ldap_server()   
            clc_ip = OpenLdap.get_clc_ip(ldap_ip)
            if not OpenLdap.p_is_vmconfig_used(clc_ip, vm.id):
                dn = 'cn=' + vm.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN
                p_delete_to_ldap(dn)
                OpenLdap.p_delvm_update_global(clc_ip, vm.id)
    return True


def p_delete_vmconfig_from_ldap(vmConfig):
    ret = False
    if(vmConfig.id == None):
        return ret
    
    vm = p_get_vmconfig_by_id(vmConfig.id)
    if(vm == None):
        return ret
    
    container = None
    if(vm.user_department_id == -1):
        container = 'default'
    else:
        department = p_euca_get_department_by_id(vm.user_department_id)
        container = get_container_by_department(department)

    if(container == None):
        return ret
    
    ldap_ip =  utility.get_ldap_server()   
    clc_ip = OpenLdap.get_clc_ip(ldap_ip)
    if not OpenLdap.p_is_vmconfig_used(clc_ip, vmConfig.id):
        dn = 'cn=' + vmConfig.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN
        ret = p_delete_to_ldap(dn)
        if ret:       
            logger.debug('delete vm :%s ' %vmConfig.id)
            OpenLdap.p_delvm_update_global(clc_ip, vmConfig.id)
    return ret

# need thermophoresis
def is_thermophoresis(vmConfig):
    ret = False
    if vmConfig.thermophoresis!=None and vmConfig.thermophoresis.is_thermophoresis !=None:
        ret = vmConfig.thermophoresis.is_thermophoresis
    return ret

def is_assign_node(vmConfig):
    ret = False
    if vmConfig.is_assign_node!=None and vmConfig.is_assign_node  and not vmConfig.node_ip=='any':
        ret = True
    return ret
    
def is_valid_vmconfig(vmConfig):
    ret = False       
    if vmConfig.user != None and vmConfig.image_id!=None and vmConfig.is_assign_node!=None:
        ret = True
    return ret

def  is_vmconfig_existed(vmConfig):
    ret = False
    oldVmConfig = p_euca_get_vmconfig(vmConfig)

    if oldVmConfig != None:
        logger.debug('is_vmconfig_existed old vm config is:%s' %str(vmConfig))                   
        if oldVmConfig.user==vmConfig.user and oldVmConfig.image_id==vmConfig.image_id and vmConfig.is_assign_node==oldVmConfig.is_assign_node and oldVmConfig.node_ip==vmConfig.node_ip:
            logger.debug('is_vmconfig_existed true')                   
            ret = True
        else:
            logger.debug('is_vmconfig_existed false')                   
    return ret

# the node is have enougth resource to run vmconfig
def is_vmconfig_can_add(vmConfig):
    ret = False
    #assigned a nc for this vmconfig
    if is_assign_node(vmConfig):
        ldap_ip =  utility.get_ldap_server()   
        clc_ip = OpenLdap.get_clc_ip(ldap_ip)    
        node_ip = vmConfig.node_ip
        
        servResource = OpenLdap.p_get_resource_by_ip(clc_ip, node_ip)
        if servResource!=None and servResource.resource!=None:
            hardResource = servResource.resource
            vmCpu = 0
            vmMemory = 0
            vmList = p_get_vmconfig_by_node(node_ip)
            
            for vm in vmList:
                vmCpu = vmCpu+vm.vm_info.vm_cpu
                vmMemory = vmMemory+vm.vm_info.vm_memory
            
            if hardResource.cpu_num < vmCpu + vmConfig.vm_info.vm_cpu + SYSTEM_CPU_NUMS:
                logger.error('is_vmconfig_can_add does not has enough cpu cores')                   
                ret = False
            elif hardResource.total_memory < vmMemory + vmConfig.vm_info.vm_memory + SYSTEM_MEMORY_SIZE:
                logger.error('is_vmconfig_can_add retuns does not has enough memory')   
                ret = False
            else:
                logger.debug('is_vmconfig_can_add retuns True')   
                ret = True
        else:
            logger.error('is_vmconfig_can_add get hardware resource failed!')             
            ret = False
    else:#do not assign nc for this vmcomfig, just add it
        ret = True#assigned a nc for this vmconfig    
    
    return ret 

def p_add_vmconfig(vmConfig):
    ret = 0

    if not is_valid_vmconfig(vmConfig): # input vmconfig is error
        logger.error('p_add_vmconfig vmconfig data is invalid: %s' %str(vmConfig))   
        return -3
    if is_vmconfig_existed(vmConfig):
        logger.error('p_add_vmconfig same vmconfig data is already existed: %s' %str(vmConfig))   
        return -11
 #   if not is_vmconfig_can_add(vmConfig):
 #       logger.error('p_add_vmconfig not enough resources to add vmconfig data: %s' %str(vmConfig))   
 #       return -12
        
    if  p_add_vmconfig_to_ldap(vmConfig):
        logger.debug('p_add_vmconfig add the vmconfig: %s' %str(vmConfig))
        ret = 0
    else:
        logger.error('p_add_vmconfig add vmconfig data to ldap failed: %s' %str(vmConfig))   
        ret = -1        
    return ret

def p_get_user_privacy(): 
    ldapip, ldapusername, ldappassword = p_get_ldap_info() 
    return p_get_value_from_ldap(ldapip, ldapusername, ldappassword, PREFRENCE_BASEDN, 'ou=prefrencePrompt', 'userPrivacy') 

def p_get_ins_report_intv():
    ldapip, ldapusername, ldappassword = p_get_ldap_info() 
    return p_get_value_from_ldap(ldapip, ldapusername, ldappassword, PREFRENCE_BASEDN, 'ou=prefrencePrompt', 'insReportIntv') 
    
def p_is_registered(servID,hostIp):
    if hostIp==None:
        return False
    ret = False
    if servID==thd_SERVICE_TYPE.CLOUD_CC:
        clusterInfo = p_get_clusterInfo_by_clusterIp(hostIp)
        if clusterInfo!=None and clusterInfo.clusterName!=None:
            ret = True
    if servID==thd_SERVICE_TYPE.CLOUD_WALRUS:
        walrusIp = None
        ldapip, username, password = p_get_ldap_info()
        walrusRes = p_get_res_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'walrusName=walrus', None)
        if walrusRes!=None and walrusRes.has_key('hostIPName') :
            walrusIp = walrusRes['hostIPName'][0]
        if walrusIp!=None and walrusIp==hostIp:
            ret = True
    if servID==thd_SERVICE_TYPE.CLOUD_NC:
        nodeInfo = p_get_nodeinfo_by_nodeIp(hostIp)
        if nodeInfo!=None and nodeInfo.clusterName!=None:
            ret = True        
    return ret

def p_euca_domain_user_logon(userName, password, domain): 
    ret = 0
    # super user
    if userName =='super' and password =='super':
        return ret
    if p_is_feature_can_use(FEATURE_SUPPORT_AD_USER): 
        user_policy = p_get_user_privacy()  
        if (user_policy == ADUSR_ONLY): 
            ret = p_check_ADusr_add_to_euca(userName, password, domain) 
        else:  #user_policy == AD_EUCA_BOTH 
            if domain!=None :
                ret = p_check_ADusr_add_to_euca(userName, password, domain)
#                if ret == -5: 
#                    if(p_euca_is_user_exist(userName)): 
#                        ret = is_password_match_euca_usrpwd(userName, password)
            else:
                if(p_euca_is_user_exist(userName)): 
                    ret = is_password_match_euca_usrpwd(userName, password)
                else:
					ret = -5             
    else: 
        if(p_euca_is_user_exist(userName)): 
            ret = is_password_match_euca_usrpwd(userName, password)
        else: 
            ret = -5
    return ret

def p_check_ADusr_add_to_euca(userName, password, domain): 
    if domain == None:
        return -1                                       # domain is error
    domaininfo = p_euca_get_domain_info_from_ldap(domain) 
    if(domaininfo == None): 
        return -1                                       # can't connect to AD 
    else: 
        lst = ['CN=',userName , ',CN=Users,', domaininfo.baseDN]
        domainUser = ''.join(lst)
        filter = 'CN=Users,' + domaininfo.baseDN
        logger.info(' userInfo: %s' % str(domaininfo))
        res = p_get_resultSet_from_ldap(domaininfo.domainHost, domainUser, password, filter, "CN=" + userName, None)         
        if(not len(res) > 0): 
            return -5                                     # the user name or password is error 
        if(not p_euca_is_user_exist(userName)): 
            domainUser = 'CN=' + domaininfo.UserNAME + ',CN=Users,' + domaininfo.baseDN 
            baseDN = 'CN=Users,' + domaininfo.baseDN 
            userInfo = p_euca_get_user_from_AD(domaininfo.domainHost, domainUser, domaininfo.encryptedPassword, baseDN, 'CN=' + userName) 
            if(userInfo != None): 
                userInfo.domain = domain 
                userInfo.popedom = 0 
                userInfo.isApproved = True 
                userInfo.isConfirmed = True 
                userInfo.isEnabled = True 
                userInfo.isAdministrator = False 
                userInfo.reservationId = 0 
                userInfo.certificateCode = p_getDigestUrlBase64(userName, 'sha512', True) 
                m = hashlib.md5() 
                m.update(password) 
                md5str = m.hexdigest()                       # get password md5 
                userInfo.bCryptedPassword = md5str
                logger.info('add user info:%s' % str(userInfo))
                if(p_euca_add_user_info(userInfo)): 
                    p_euca_add_auth_user(userInfo) 
                else: 
                    return -4                                 # add the AD user to ldap (euca user) is error  
            else: 
                return -3                                   # get user info from AD is error 
        else: 
            if(not p_update_user_password(userName, password)): 
                return -6 
    return 0

def is_password_match_euca_usrpwd(userName, password): 
    ret = 0
    ldapip, ldapusername, ldappassword = p_get_ldap_info() 
    m = hashlib.md5() 
    m.update(password) 
    md5str = m.hexdigest()    # get password md5 
    usrpwd = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'cn=' + userName,'userPassword') 
    if(md5str == usrpwd): 
        ret = 0
    else: 
        ret = -2
    return ret

def p_euca_reg_get_feature_switch():
    ldapip, username, password = p_get_ldap_info()
    values = p_get_value_set_from_ldap(ldapip, username, password, FEATURL_CONTROL_BASEDN, 'ou=featureControl','featuresswitch')
    if(values != None and len(values) > 0):
        i = 0
        while(i < len(values)):
            featureStr = values[i]
            feaList = featureStr.split(',')
            if(len(feaList) == 4):
                featureDic = {}
                featureDic['featureNo'] = feaList[0]
                featureDic['featureName'] = feaList[1]
                featureDic['featureState'] = feaList[2]
                featureDic['quantity'] = int(feaList[3])
                featurelist[feaList[0]] = featureDic
            i = i + 1   
    return


def p_luhya_get_available_images_by_user(userName):
    ldapip, username, password = p_get_ldap_info()
    img_list = p_euca_get_images_by_user(userName) 
    return img_list


def p_is_feature_can_use(featureID):
    ret = False
    if(featurelist != None):
        featureDic = featurelist[featureID]
        if(featureDic != None):
            state = featureDic['featureState'].strip().lower()
            if state == FEATURE_ON :
                ret = True
    return ret


def p_get_users_by_department(departmentID):
    users = []
    ldapip, username, password = p_get_ldap_info()
    userlist = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
    for userInfo in userlist:
        if(userInfo.sSeriesName != None) and (len(userInfo.sSeriesName.strip()) > 0) and (
        userInfo.seriesID != None)and (userInfo.seriesID == departmentID ):
            users.append(userInfo)
    logger.info('p_get_users_by_department(%s)' % (users))
    return users


def p_get_nodeinfo_by_nodeIp(nodeIp):
    nodeInfo = None
    logger.debug('p_get_nodeinfo_by_nodeIp(%s)' % (nodeIp))
    ldapip, username, password = p_get_ldap_info()
    list_info = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP=' + nodeIp)
    if(len(list_info) > 0):
        nodeInfo = list_info[0]
    return nodeInfo


def p_get_all_AD_user_info(domain):
    users = []
    domaininfo = p_euca_get_domain_info_from_ldap(domain)
    if domaininfo==None:
        return users
    lst = ['CN=', domaininfo.UserNAME, ',CN=Users,', domaininfo.baseDN]
    domainUser = ''.join(lst)
    baseDn = 'CN=Users,' + domaininfo.baseDN
    filter = 'objectclass=user'
    res = p_get_resultSet_from_ldap(domaininfo.domainHost, domainUser, domaininfo.encryptedPassword, baseDn, filter,
                                    None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for user in res:
            userInfo = thd_UserInfo()
            userInfo.domain = domain
            userInfo.popedom = 0
            userInfo.isApproved = True
            userInfo.isConfirmed = True
            userInfo.isEnabled = True
            userInfo.isAdministrator = False
            userInfo.reservationId = 0
            m = hashlib.md5()
            m.update(DEFAULT_PASS)
            md5str = m.hexdigest()                       # get password md5
            userInfo.bCryptedPassword = md5str
            if(user[0][1].get('cn') != None):
                userInfo.userName = user[0][1].get('cn')[0]
                userInfo.realName = user[0][1].get('cn')[0]
                userInfo.sLogonName = user[0][1].get('cn')[0]
                userInfo.confirmationCode = p_getDigestUrlBase64(user[0][1].get('cn')[0], 'sha512', False)
                userInfo.certificateCode = p_getDigestUrlBase64(user[0][1].get('cn')[0], 'sha512', True)
            if user[0][1].get('department') != None:
                department = user[0][1].get('department')[0]
                if(not p_euca_is_department_exist(department)):
                    p_euca_add_department(department)
                userInfo.sSeriesName = department
                userInfo.seriesID = p_euca_get_departmentId_by_department(department)
            else:
                userInfo.sSeriesName = 'default'
                userInfo.seriesID = -1
            if(user[0][1].get('accountExpires') != None):
                userInfo.passwordExpires = int(user[0][1].get('accountExpires')[0])
            users.append(userInfo)
    return users


def p_import_AD_users(domain):
    users = p_get_all_AD_user_info(domain)
    if(len(users) > 0):
        for userInfo in users:
            if(p_euca_add_user_info(userInfo)):
                p_euca_add_auth_user(userInfo)
    return

def p_has_hz(text):
    '''check the string has chinese '''
    hz_yes = False
    unStr = unicode(text, 'utf-8')
    for uch in unStr:       
        if uch >= u'\u4e00' and uch<=u'\u9fa5' :
            hz_yes = True
            break   
    return hz_yes



class p_import_AD_user_thread(threading.Thread):
    def __init__(self, domain):
        threading.Thread.__init__(self)
        self.domain = domain

    def run(self):
        logger.info('p_import_AD_user_thread starting ...')
        p_import_AD_users(self.domain)


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

class p_get_clc_ip_thread(threading.Thread):  
    def __init__(self, ):
        threading.Thread.__init__(self)
    def run(self):
        while True:
            global g_clc_ip
            time.sleep(1)
            g_clc_ip = p_get_value_from_ldap(g_ldap_ip, g_user_name, g_user_passwd, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
            if g_clc_ip!=None:
                break

def p_create_import_AD_user_thread(domain):
    processid = p_import_AD_user_thread(domain)
    processid.start()


def p_update_user_password(userName, password):
    ret = False
    if(password == None or userName == None):
        return ret
    if(p_euca_is_user_exist(userName)):
        list_attr = []
        attr = None
        m = hashlib.md5()
        m.update(password)
        md5Password = m.hexdigest()
        attr = (ldap.MOD_REPLACE, 'carLicense', md5Password)
        list_attr.append(attr)
        attr = (ldap.MOD_REPLACE, 'userPassword', md5Password)
        list_attr.append(attr)
        dn = 'cn=' + userName + ',' + USER_INFO_BASEDN
        ret = p_update_to_ldap(dn, list_attr)
    return ret

def p_add_euca_user(userInfo):
    ret = False           
    if(userInfo.sSeriesName==None or userInfo.userName==None):
        return ret
    usrInfo = thd_UserInfo()
    usrInfo.userName = userInfo.userName
    usrInfo.sLogonName = userInfo.userName
    usrInfo.realName = userInfo.userName
    usrInfo.sSeriesName = userInfo.sSeriesName
    usrInfo.email = userInfo.email
    usrInfo.seriesID = p_euca_get_departmentId_by_department(userInfo.sSeriesName)
    usrInfo.bCryptedPassword = userInfo.bCryptedPassword
    usrInfo.reservationId = -1
    usrInfo.confirmationCode = p_getDigestUrlBase64(userInfo.userName, 'sha512', False)
    usrInfo.certificateCode = p_getDigestUrlBase64(userInfo.userName, 'sha512', True)
    if userInfo.popedom!=None :
        usrInfo.popedom = userInfo.popedom
    else:
		usrInfo.popedom = 0
    usrInfo.isEnabled = True
    usrInfo.isConfirmed = True
    usrInfo.isApproved = True
    usrInfo.isPrivateImgCreated = False
    if usrInfo.popedom==int(ADMIN_POPEDOM) :
        usrInfo.isAdministrator = True
    else:
        usrInfo.isAdministrator = False
    usrInfo.passwordExpires = int(time.time())+PASSWORD_EXPIRES
    usrInfo.maxPrivateInstances=userInfo.maxPrivateInstances    
    if(p_euca_add_user_info(usrInfo)):
        ret = p_euca_add_auth_user(usrInfo)
    return ret

def p_delete_domain_from_ldap(domInfo):
    if(domInfo.domain==None):
        return False
    dn = 'cn='+domInfo.domain+','+PREFRENCE_BASEDN
    return p_delete_to_ldap(dn)

def p_is_domain_exist(domain):
    ldapip,ldapusername,ldappassword = p_get_ldap_info()
    dmn = p_get_value_from_ldap(ldapip,ldapusername,ldappassword,PREFRENCE_BASEDN,'cn='+domain,'cn')
    if(dmn==None):
      return False
    else:
      return True

def check_ip(ip):
    r = re.compile('((25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}(25[0-5]|2[0-4]\d|1\d\d|\d{1,2})')
    if r.match(ip):
       return True
    else:
       return False

def isNULL(x):
    if(x==None):
        return True
    if(re.match('^\s*$',x)):
        return True

def p_add_domain_to_ldap(domInfo):
    logger.info('p_add_domain_to_ldap: %s' % str(domInfo))
    ret = False
    if(domInfo.domain==None or domInfo.domainHost==None or domInfo.UserNAME==None or domInfo.encryptedPassword==None or domInfo.baseDN==None or domInfo.port==None):
        return ret

    attrs = {}
    if (check_ip(domInfo.domainHost)):
        attrs['domainHost'] = domInfo.domainHost
    else:
        return ret

    if(not p_is_domain_exist(domInfo.domain)):
        newDN = 'cn=' + domInfo.domain +','+ PREFRENCE_BASEDN
        attrs['objectclass'] = ['DOMAIMINFO']
        #attrs['cn'] = domInfo.domain
        attrs['domain'] = domInfo.domain
        attrs['UserNAME'] = domInfo.UserNAME
        attrs['encryptedPassword'] = domInfo.encryptedPassword
        attrs['baseDN'] = domInfo.baseDN
        attrs['port'] = str(domInfo.port) 
 
        ret = p_add_to_ldap(newDN, attrs)	  
    return ret

def p_modify_domain(domInfo):
    ret = False
    if(domInfo.domain == None):
        return ret
    if(not p_is_domain_exist(domInfo.domain)):
        return ret 
    dn = 'cn='+domInfo.domain+','+PREFRENCE_BASEDN
    list_attr = []
    if(domInfo.UserNAME!=None):
        attr = (ldap.MOD_REPLACE, 'UserNAME', domInfo.UserNAME) 
        list_attr.append(attr)
    if(domInfo.encryptedPassword!=None):
        attr = (ldap.MOD_REPLACE, 'encryptedPassword', domInfo.encryptedPassword)
        list_attr.append(attr)
    if(domInfo.baseDN!=None):
        attr = (ldap.MOD_REPLACE, 'baseDN', domInfo.baseDN)
        list_attr.append(attr)
    if(domInfo.port!=None):
        attr = (ldap.MOD_REPLACE, 'port', str(domInfo.port))
        list_attr.append(attr)
    if(domInfo.domainHost!=None):
        if (check_ip(domInfo.domainHost)):
            attr = (ldap.MOD_REPLACE, 'domainHost', domInfo.domainHost)
            list_attr.append(attr)
        else:
            return ret
    return p_update_to_ldap(dn ,list_attr)

def p_euca_get_uuid_from_auth(username):
    ldapip,ldapusername,ldappassword = p_get_ldap_info()
    uuid = p_get_value_from_ldap(ldapip,ldapusername,ldappassword,AUTH_INFO_BASEDN,'cn='+username,'uuid')
    return uuid

def p_euca_modify_auth_user(uuid, userInfo):
    dnauth = 'uuid='+uuid+','+AUTH_INFO_BASEDN
    list_attrauth = []
    if(userInfo.isEnabled!=None):
        attr = None
        if(userInfo.isEnabled):
            attr =(ldap.MOD_REPLACE, 'isEnable', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isEnable', 'FALSE') 
        list_attrauth.append(attr)
    if(userInfo.isAdministrator!=None):
        attr = None
        if(userInfo.isAdministrator):
            attr =(ldap.MOD_REPLACE, 'isAdministrator', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isAdministrator', 'FALSE') 
        list_attrauth.append(attr)
    return p_update_to_ldap(dnauth, list_attrauth)


def p_euca_modify_user_info(userInfo):
    ret = False
    logger.debug('p_euca_modify_user_info:%s' %str(userInfo))
    dn = 'cn='+userInfo.userName+','+USER_INFO_BASEDN
    list_attr = []
    if(userInfo.realName!=None):
        attr = (ldap.MOD_REPLACE, 'sn', None)
        if(len(userInfo.realName) > 0):
            attr = (ldap.MOD_REPLACE, 'sn', userInfo.realName)
        list_attr.append(attr)
        attr = (ldap.MOD_REPLACE, 'realNAME', None)
        if(len(userInfo.realName) > 0):         
            attr = (ldap.MOD_REPLACE, 'realNAME', userInfo.realName) 
        list_attr.append(attr)
                        
    if(userInfo.seriesID!=None):
        attr = (ldap.MOD_REPLACE, 'seriesID', str(userInfo.seriesID))
        list_attr.append(attr)
    if(userInfo.sSeriesName!=None):
        attr = (ldap.MOD_REPLACE, 'seriesNAME', None)
        if(len(userInfo.sSeriesName) > 0):
            attr = (ldap.MOD_REPLACE, 'seriesNAME', userInfo.sSeriesName)
        list_attr.append(attr)
    if(not isNULL(userInfo.bCryptedPassword)):
        attr = (ldap.MOD_REPLACE, 'userPassword', userInfo.bCryptedPassword)
        list_attr.append(attr)
        attr = (ldap.MOD_REPLACE, 'carLicense', userInfo.bCryptedPassword)
        list_attr.append(attr)

    if(userInfo.sLogonName!=None):
        attr = (ldap.MOD_REPLACE, 'displayName', None)
        if(len(userInfo.sLogonName) > 0):
            attr = (ldap.MOD_REPLACE, 'displayName', userInfo.sLogonName)
        list_attr.append(attr)
    if(userInfo.email!=None):
        attr = (ldap.MOD_REPLACE, 'email', None)
        if(len(userInfo.email) > 0):
            attr = (ldap.MOD_REPLACE, 'email', userInfo.email)
        list_attr.append(attr)
    if(userInfo.isApproved!=None):
        attr = None
        if(userInfo.isApproved):
            attr =(ldap.MOD_REPLACE, 'isApproved', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isApproved', 'FALSE') 
        list_attr.append(attr)
    if(userInfo.isConfirmed!=None):
        attr = None
        if(userInfo.isConfirmed):
            attr =(ldap.MOD_REPLACE, 'isConfirmed', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isConfirmed', 'FALSE') 
        list_attr.append(attr)
    if(userInfo.isEnabled!=None):
        attr = None
        if(userInfo.isEnabled):
            attr =(ldap.MOD_REPLACE, 'isEnable', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isEnable', 'FALSE') 
        list_attr.append(attr)
    if(userInfo.isPrivateImgCreated!=None):
        attr = None
        if(userInfo.isPrivateImgCreated):
            attr =(ldap.MOD_REPLACE, 'isPrivateImgCreated', 'TRUE')
        else:
            attr =(ldap.MOD_REPLACE, 'isPrivateImgCreated', 'FALSE') 
        list_attr.append(attr)
    if(userInfo.popedom!=None):
        attr = (ldap.MOD_REPLACE, 'popedom', str(userInfo.popedom))
        list_attr.append(attr)
    if(userInfo.passwordExpires!=None):
        attr = (ldap.MOD_REPLACE, 'passwordExpires', str(userInfo.passwordExpires))
        list_attr.append(attr)
    if(userInfo.maxPrivateInstances!=None):
        attr = (ldap.MOD_REPLACE, 'MaxPrivateInstances', str(userInfo.maxPrivateInstances))
        list_attr.append(attr)    
    return p_update_to_ldap(dn ,list_attr)
 

def p_euca_del_user_info(username):
    dn = 'cn='+username+','+USER_INFO_BASEDN
    p_delete_to_ldap(dn)
    uuid = p_euca_get_uuid_from_auth(username)
    if(not isNULL(uuid)):
        dnauth = 'uuid='+uuid+','+AUTH_INFO_BASEDN
        p_delete_to_ldap(dnauth)
    return True


def p_del_vmconfig_by_user(username):
    vmList = p_get_vmconfigs_by_user(username)
    if(len(vmList) > 0):
        for vm in vmList:
            container = None
            if(vm.departmentID == None):
                    department = p_get_department_by_user(vm.user)
                    if(department == None):
                        container = 'default'
                    else:
                        container = get_container_by_department(department)
            else:
                if(vm.departmentID == -1):
                    container = 'default'
                else:
                    department = p_euca_get_department_by_id(vm.departmentID)
                    container = get_container_by_department(department)
            if(container == None):
                continue
            dn = 'cn=' + vm.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN
            ret = p_delete_to_ldap(dn)
            if ret:
                ldap_ip =  utility.get_ldap_server()   
                clc_ip = OpenLdap.get_clc_ip(ldap_ip)

                OpenLdap.p_delvm_update_global(clc_ip, vm.id)
    return True


def p_del_image_by_user(username):
    imgList = p_euca_get_images_by_user(username)
    if(len(imgList) > 0):
        for img in imgList:
            if(img.imageCategory == 0):
                dn = 'imageId=' + img.imageId + ',' + IMAGE_BASEDN
                ret = p_delete_to_ldap(dn)
                if ret:
                    ldap_ip =  utility.get_ldap_server()   
                    clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                    
                    OpenLdap.p_delimg_update_global(clc_ip,  img.imageId)
    return True

def p_euca_del_department(department):
    ret = False
    if(p_euca_is_department_exist(department)):
        dn = 'cn=' + department + ',' + DEPARTMENT_BASEDN
        p_delete_to_ldap(dn)
    return True
    
def p_department_can_be_delete(preDepartment):
	logger.info('p_department_can_be_delete()')
	ret = False
	if(preDepartment == None):
		return ret    
	ldapip,ldapusername,ldappassword = p_get_ldap_info()
	res = p_get_resultSet_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'seriesNAME='+preDepartment, None)
	if len(res) > 0 and len(res[0][0][1]) > 0:
		return ret
	res = p_get_resultSet_from_ldap(ldapip, ldapusername, ldappassword, VM_CONFIG_BASEDN, 'hostname='+preDepartment, None)
	if len(res) > 0 and len(res[0][0][1]) > 0:
		return ret
	return True       



def p_get_all_service_ip():
    ipList = []
    ldapip, username, password = p_get_ldap_info()
    ipList.append(ldapip)
    clcip = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
    if clcip!=None and clcip!=ldapip :
        ipList.append(clcip)
    res = p_get_resultSet_from_ldap(ldapip, username, password, EUCA_CONFIG_BASEDN, 'ou=*', None)   
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for eucaConf in res:
            if eucaConf[0][1].get('ou') != None and eucaConf[0][1].get('ou')[0]!='eucaconfig':
                serviceName = eucaConf[0][1].get('ou')[0]
                baseDn = 'ou='+serviceName+','+EUCA_CONFIG_BASEDN
                configRes = p_get_resultSet_from_ldap(ldapip, username, password,baseDn , 'uuid=*', None)
                if len(configRes) > 0 and len(configRes[0][0][1]) > 0:
                    for serviceConf in configRes:
                        hostIp = None
                        if serviceName == 'nodeconfig':
                            if serviceConf[0][1].get('IP')!=None:
                                hostIp = serviceConf[0][1].get('IP')[0]
                        else:
                            if serviceConf[0][1].get('hostIPName')!=None:
                                hostIp = serviceConf[0][1].get('hostIPName')[0]				
                        if hostIp!=None :
                            hasThis = False
                            for tempIp in ipList:
                                if tempIp == hostIp :
                                    hasThis = True
                                    break
                            if not hasThis :
                                ipList.append(hostIp)					
    return ipList					

def p_get_services_by_ip(ipAddress):
    services = []
    ldapip, username, password = p_get_ldap_info()
    if ldapip == ipAddress:
        services.append(thd_SERVICE_TYPE.CLOUD_REGISTRY)
    clcip = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
    if ipAddress == clcip :
        services.append(thd_SERVICE_TYPE.CLOUD_CLC)
    cluster = p_get_value_from_ldap(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'clusterName')    
    if cluster!=None :
        services.append(thd_SERVICE_TYPE.CLOUD_CC)
    walrus = p_get_value_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'walrusName')
    if walrus!=None :
        services.append(thd_SERVICE_TYPE.CLOUD_WALRUS)
    nodeIp = p_get_value_from_ldap(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP='+ipAddress, 'cn')		    
    if nodeIp!=None :
        services.append(thd_SERVICE_TYPE.CLOUD_NC)
    webIp = p_get_value_from_ldap(ldapip, username, password, WEB_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'hostIPName')		    
    if webIp!=None :
        services.append(thd_SERVICE_TYPE.CLOUD_WEB)
    logger.info('p_get_services_by_ip :%s' % str(services))
    return services

def p_is_service_start():
    serviceName = CLOUD_REGISTRY
    return utility.p_is_service_start(serviceName)
    
def p_start_service():
    serviceName = CLOUD_REGISTRY
    return utility.p_start_service(serviceName)
 
def p_stop_service():
    serviceName = CLOUD_REGISTRY
    return utility.p_stop_service(serviceName)

def p_getMigrateNodeList(ldapip, username, password, baseDN, searchFilter):
    nodeList = []
    ncRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, None)
    for ncInfo in ncRes:
        uuid = None
        if ncInfo[0][1].get('uuid') != None:
            uuid = ncInfo[0][1].get('uuid')[0]   
        sourceIP = None
        if ncInfo[0][1].get('IP') != None:
            sourceIP = ncInfo[0][1].get('IP')[0]   
        isThermophoresis = False
        if ncInfo[0][1].get('isThermophoresis') != None:
            if(cmp(ncInfo[0][1].get('isThermophoresis')[0].lower(), 'true') == 0 ):
                isThermophoresis = True
            else:
                isThermophoresis = False   
        targetIP = None
        if ncInfo[0][1].get('thermophoresisNode') != None:
            targetIP = ncInfo[0][1].get('thermophoresisNode')[0]
        if(isThermophoresis == True):
            nodeInfo = thd_nodeMigrateInfo(\
                id=uuid,\
                sourceIP=sourceIP,\
                targetIP=targetIP)
            nodeList.append(nodeInfo)        
    return nodeList


def p_set_make_image_node(nodeIp):
    list_attr = []
    if nodeIp!=None:
        dn = 'ou=prefrencePrompt,cn=clc,o=cloudbot,o=sinobot'
        attr = (ldap.MOD_REPLACE, 'MakeImageNode', nodeIp)
        list_attr.append(attr)
        p_update_to_ldap(dn, list_attr)
    return True

    
def p_getMigrateNodeUUIDByHostIP(ldapip, username, password, baseDN,hostIP):
    uuid = None
    ncRes = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'uuid=*', None)
    for ncInfo in ncRes:
        if ncInfo[0][1].get('IP') != None:
            if(cmp(ncInfo[0][1].get('IP')[0], hostIP) == 0 ):
                uuid = ncInfo[0][1].get('uuid')[0] 
                break		  
    return uuid
    	
def p_get_node_migrate_list():
    logger.info('p_get_node_migrate_list()')
    ldapip, username, password = p_get_ldap_info()
    list_info = p_getMigrateNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'uuid=*')
    return list_info  

      
       
def p_delete_node_migrate_pair(sourceIP, targetIP):
    logger.info('p_delete_node_migrate_pair()')
    ldapip, username, password = p_get_ldap_info()
    if(sourceIP == None or targetIP == None):
		return False;
    uuid = p_getMigrateNodeUUIDByHostIP(ldapip, username, password, NODE_CONFIG_BASEDN, sourceIP)
    if(uuid == None):
        return False
    dn = 'uuid='+uuid+','+NODE_CONFIG_BASEDN
    list_attr = []
    if(targetIP!=None and len(targetIP) > 0):
        attr = (ldap.MOD_REPLACE, '', None)
        attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'FALSE')
        list_attr.append(attr)   
        attr = (ldap.MOD_REPLACE, 'thermophoresisNode', '0.0.0.0') 
        list_attr.append(attr)
    return p_update_to_ldap(dn ,list_attr) 
     
def p_add_node_migrate_pair(sourceIP, targetIP):
    logger.info('p_add_node_migrate_pair()')
    ldapip, username, password = p_get_ldap_info()
    if(sourceIP == None or targetIP == None):
		return False;
    uuid = p_getMigrateNodeUUIDByHostIP(ldapip, username, password, NODE_CONFIG_BASEDN, sourceIP)
    if(uuid == None):
        return False
    dn = 'uuid='+uuid+','+NODE_CONFIG_BASEDN
    list_attr = []
    if(targetIP!=None and len(targetIP) > 0):
        attr = (ldap.MOD_REPLACE, '', None)
        attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'TRUE')
        list_attr.append(attr)   
        attr = (ldap.MOD_REPLACE, 'thermophoresisNode', targetIP) 
        list_attr.append(attr)
    return p_update_to_ldap(dn ,list_attr) 

def p_get_migrate_Info_list(userName):
    logger.info('p_get_migrate_Info_list()')
    ins = []
    vms = p_get_vmconfigs_by_user(userName)
    for vm in vms:
        if(vm.user!=None and vm.user!='any' and vm.imageId!=None and vm.imageId!='any'):
            migrateInfo = thd_migrateInfo()
            if(vm.thermophoresis == None or vm.thermophoresis.isThermophoresis == False):
				continue;
            migrateInfo.machinename = vm.machinename
            migrateInfo.user = vm.user
            migrateInfo.imageId = vm.imageId 
            migrateInfo.publicIp = vm.netInfo.publicIp
            migrateInfo.sourceIP = vm.nodeIp
            migrateInfo.targetIP = vm.thermophoresis.thermophoresisNode
            ins.append(migrateInfo)            
    return ins
        
def p_get_available_snapshot_num(userName,imageID):
    ret = -1
    if(userName == None or imageID == None):
        return ret
    vmcfgList = p_get_all_vmconfig()
    if(len(vmcfgList) > 0):
        for vm in vmcfgList:
            if(vm.user == userName and vm.image_id == imageID):
                if(vm.snapshot!=None and vm.snapshot.is_snapshot):
                    ret = vm.snapshot.max_snapshot
    logger.info('p_get_available_snapshot_num maxSnapshot=%s'%ret)
    return ret

def p_get_current_snapshot_id(userName,imageID):
    ret = -1
    if(userName == None or imageID == None):
        return ret
    ldapip, username, password = p_get_ldap_info()
    seriesRes = p_get_resultSet_from_ldap(ldapip, username, password, SNAPSHOT_BASEDN, 'ou='+userName+imageID, None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        for series in seriesRes:
            if(series[0][1].get('currentSnapshotTag') != None):
                ret = (int)(series[0][1].get('currentSnapshotTag')[0])
                break
    return ret

def p_add_snapshot_container(userName,imageID):
    ret = None
    if(userName == None or imageID == None):
        return None
    ldapip, username, password = p_get_ldap_info()
    container = userName+imageID
    newConDN = 'ou=' + container + ',' + SNAPSHOT_BASEDN
    attrsCon = {}
    attrsCon['objectClass'] = 'SNAPSHOTCONTAINER'
    attrsCon['imageId'] = imageID
    attrsCon['UserNAME'] = userName
    attrsCon['currentSnapshotTag'] = '-1'
    if p_add_to_ldap(newConDN, attrsCon):
        ret = container
    return ret
    
def p_set_current_snapshot_id(userName,imageID,snapshotID):
    ret = False
    if(userName == None or imageID == None):
        return ret
    container = p_get_snapshot_container(userName,imageID)
    if(container == None):
        return ret
    list_attr = []
    attr = None
    attr = (ldap.MOD_REPLACE, 'currentSnapshotTag', str(snapshotID))
    list_attr.append(attr)
    dn = 'ou=' + container + ',' + SNAPSHOT_BASEDN
    ret = p_update_to_ldap(dn, list_attr)  		
    return ret
    
    
def p_get_snapshot_container(userName,imageID):
    container = None
    if(userName == None or imageID == None):
        return None
    ldapip, username, password = p_get_ldap_info()
    seriesRes = p_get_resultSet_from_ldap(ldapip, username, password, SNAPSHOT_BASEDN, 'ou='+userName+imageID, None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        container = userName+imageID
    logger.info('p_get_snapshot_container container=%s'%container)
    return container
    
def p_get_snapshotInfo_by_id(userName,imageID,snapshotID) :
    snapshotInfo = None
    if(userName == None or imageID == None or snapshotID == None):
        return snapshotInfo
    list = p_get_snapshot_list(userName,imageID)
    for snpinfo in list:
        if(snpinfo.id == snapshotID):
            snapshotInfo = snpinfo
            break
    logger.info('p_get_snapshotInfo_by_id:%s'%snapshotInfo)
    return snapshotInfo
		
def p_get_snapshot_list(userName,imageID):
    list=[]
    if(userName == None or imageID == None):
        return list
    container = p_get_snapshot_container(userName,imageID)
    if(container == None):
		return list
    ldapip, username, password = p_get_ldap_info()
    baseDN = 'ou=' + container + ',' + SNAPSHOT_BASEDN 
    results = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'id=*', None)
    logger.info('p_get_snapshot_list:%s'%results)
    for snpinfo in results:
        id = 1
        if snpinfo[0][1].get('id') != None:
            id = int(snpinfo[0][1].get('id')[0])   
        
        snapshotName = None
        if snpinfo[0][1].get('snapshotName') != None:
            snapshotName = snpinfo[0][1].get('snapshotName')[0]  
            
        description = None
        if snpinfo[0][1].get('description') != None:
            description = snpinfo[0][1].get('description')[0] 
        
        snapshotTag = None
        if snpinfo[0][1].get('snapshotTag') != None:
            snapshotTag = snpinfo[0][1].get('snapshotTag')[0]  
             
        snapshotDate = None
        if snpinfo[0][1].get('createDate') != None:
            snapshotDate = snpinfo[0][1].get('createDate')[0]   
        
        vmSize = 0
        if snpinfo[0][1].get('size') != None:
            vmSize = int(snpinfo[0][1].get('size')[0])   
                          
        snapshotInfo = thd_snapshot(\
                id=id,\
                imageID=imageID,\
                userName=userName,\
                snapshotName=snapshotName,\
                description = description,\
                snapshotTag = snapshotTag,\
                vmSize = vmSize,\
                snapshotDate = snapshotDate)
        list.append(snapshotInfo)       
    return list

def p_add_snapshot(snapshotInfo):
    ret = False
    if(snapshotInfo == None or snapshotInfo.userName == None or snapshotInfo.imageID == None or snapshotInfo.id == -1):
        return ret
    container = p_get_snapshot_container(snapshotInfo.userName,snapshotInfo.imageID)
    if(container == None):
        container = p_add_snapshot_container(snapshotInfo.userName,snapshotInfo.imageID)
        if( container== None):
            return ret
    newConDN = 'id='+str(snapshotInfo.id)+','+'ou=' + container + ',' + SNAPSHOT_BASEDN
    logger.info('p_add_snapshot_job  newConDN:%s' % newConDN)
    attrsCon = {}
    attrsCon['objectClass'] = 'LUHYASNAPSHOTINFO'
    attrsCon['snapshotName'] = snapshotInfo.snapshotName
    attrsCon['description'] = snapshotInfo.description
    attrsCon['createDate'] = snapshotInfo.snapshotDate
    #attrsCon['snapshotTag'] = snapshotInfo.snapshotTag
    #attrsCon['size'] = snapshotInfo.vmSize
    ret = p_add_to_ldap(newConDN, attrsCon)
    return ret
	 
def p_modify_snapshot(snapshotInfo):
    ret=False
    if(snapshotInfo == None or snapshotInfo.userName == None or snapshotInfo.imageID == None or snapshotInfo.id == -1):
        return ret
    container = p_get_snapshot_container(snapshotInfo.userName,snapshotInfo.imageID)
    if(container == None):
        return ret
    baseDN = 'id='+str(snapshotInfo.id)+','+'ou=' + container + ',' + SNAPSHOT_BASEDN
   
    list_attr = []
    attr = None
    if(snapshotInfo.snapshotName != None):
        attr = (ldap.MOD_REPLACE, 'snapshotName', snapshotInfo.snapshotName)
        list_attr.append(attr)
    if(snapshotInfo.description != None):
        attr = (ldap.MOD_REPLACE, 'description', snapshotInfo.description)
        list_attr.append(attr)
    if(len(list_attr) > 0):
        ret = p_update_to_ldap(baseDN, list_attr)  	
    return ret
	
def p_delete_snapshot(userName,imageID,snapshotID):
    ret=False
    if(userName == None or imageID == None or snapshotID == -1):
        return ret
    currentSnpID = p_get_current_snapshot_id(userName,imageID)
    if(currentSnpID == snapshotID):
        p_set_current_snapshot_id(userName,imageID,-1)
    container = p_get_snapshot_container(userName,imageID)
    if(container == None):
        return ret
    baseDN = 'id='+str(snapshotID)+','+'ou=' + container + ',' + SNAPSHOT_BASEDN
    ret= p_delete_to_ldap(baseDN)
    return ret
	
def p_get_available_snapshot_id(userName,imageID):
    ret = 1
    if(userName == None or imageID == None):
        return ret
    container = p_get_snapshot_container(userName,imageID)
    if(container == None):
        return ret
    ldapip, username, password = p_get_ldap_info()
    baseDN = 'ou=' + container + ',' + SNAPSHOT_BASEDN 
    results = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'id=*', None)
    maxID = 0
    for snpinfo in results:
        if snpinfo[0][1].get('id') != None:
            id = int(snpinfo[0][1].get('id')[0])
            if(id > maxID):
                maxID = id 
    ret = maxID+1 
    logger.info('p_get_available_snapshot_id() id=%s'%ret)       
    return ret

def p_init_clc_system_config(clcIp):
    ldapip, username, password = p_get_ldap_info()
    ret = False
    baseDN = CLC_BASEDN
    results = p_get_res_from_ldap(ldapip, username, password, baseDN, 'cn=systemconfiguration', None)
    if results!=None and results.has_key('cloudHost'):  # update clc info
        list_attr = []
        attr = None        
        attr = (ldap.MOD_REPLACE, 'cloudHost', clcIp)
        list_attr.append(attr)
        dn = 'cn=systemconfiguration,' + baseDN
        ret = p_update_to_ldap(dn, list_attr)        
    else:                                        # add clc info
        newDN = 'cn=systemconfiguration,' + baseDN
        attrs = {}
        attrs['objectclass'] = ['SYSTEMCONFIGURATION']
        attrs['cloudHost'] = clcIp
        attrs['dnsDomain'] = 'localhost'
        attrs['doDynamicPublicAddresses'] = 'TRUE'
        attrs['maxUserPublicAddresses'] = '5' 
        attrs['nameserver'] = 'nshost.localhost'
        attrs['nameserverAddress'] = '127.0.0.1'         
        attrs['systemReservedPublicAddresses'] = '10'         
        ret = p_add_to_ldap(newDN, attrs)
    return ret     

def p_init_euca_config():
    ldapip, username, password = p_get_ldap_info()
    ret = False
    baseDN = CLC_BASEDN
    results = p_get_res_from_ldap(ldapip, username, password, baseDN, 'cn=eucalyptusconf', None)
    if results==None or not results.has_key('EUCALYPTUS'):                                        # add clc info
        newDN = 'cn=eucalyptusconf,' + baseDN
        attrs = {}
        attrs['objectclass'] = ['EUCALYPTUSCONF']
        attrs['CCPORT'] = '80'
        attrs['DISABLEDNS'] = 'Y'
        attrs['DISABLEISCSI'] = 'Y'
        attrs['ENABLEWSSECURITY'] = '5' 
        attrs['EUCALYPTUS'] = '/var/lib/eucalyptus/'
        attrs['HYPERVISOR'] = 'kvm'         
        attrs['LOGLEVEL'] = 'DEBUG'
        attrs['MANUALINSTANCESCLEANUP'] = '0'
        attrs['MAXCORES'] = '40'
        attrs['VNETADDRSPERNET'] = '32'
        attrs['VNETBRIDGE'] = 'virbr0'
        attrs['VNETMODE'] = 'SYSTEM'
        attrs['VNETPRIVINTERFACE'] = 'eth0'
        attrs['VNETPUBINTERFACE'] = 'eth0'
        logger.info('p_init_euca_config : %s' %str(attrs))
        ret = p_add_to_ldap(newDN, attrs)
    else:
        ret=True
    return ret

def p_init_clc_info(clcIp):
    if clcIp==None:
        return False
    ret = p_init_clc_system_config(clcIp)
    p_init_euca_config()
    return ret
    
    
    
def p_init_walrus_info(walrusIp):
    ret = False
    ldapip, username, password = p_get_ldap_info()
    results = p_get_res_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'walrusName=walrus', None)
    if results!=None and results.has_key('walrusName'):  #update walrus info  
        logger.info('p_init_walrus_info:%s' %str(results))
        walrusid = results['uuid'][0]
        list_attr = []
        attr = None        
        attr = (ldap.MOD_REPLACE, 'hostIPName', walrusIp)
        list_attr.append(attr)
        dn = 'uuid='+walrusid+',' + WALRUS_CONFIG_BASEDN
        ret = p_update_to_ldap(dn, list_attr)
    else:
        strUuid = str(uuid.uuid4())
        newDN = 'uuid='+strUuid+',' + WALRUS_CONFIG_BASEDN
        attrs = {}
        attrs['objectclass'] = ['WALRUSCONFIG']
        attrs['hostIPName'] = walrusIp
        attrs['port'] = '80'
        attrs['walrusName'] = 'walrus'
        ret = p_add_to_ldap(newDN, attrs)
        
    clc_ip = OpenLdap.get_clc_ip(ldapip)    
    OpenLdap.p_add_service_resource(clc_ip,  walrusIp,thd_SERVICE_TYPE.CLOUD_WALRUS)
    return ret

def p_init_cluster_info(clusterInfo):
    ret = False
    if clusterInfo==None or clusterInfo.clusterName==None or clusterInfo.hostIp==None:
        return ret
    ldapip, username, password = p_get_ldap_info()
    results = p_get_res_from_ldap(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'hostIPName='+clusterInfo.hostIp, None)
    if results!=None and results.has_key('clusterName') > 0:  #update cluster info
        clusterid = results['uuid'][0]
        list_attr = []
        attr = None 
        attr = (ldap.MOD_REPLACE, 'hostIPName', clusterInfo.hostIp)
        list_attr.append(attr)
        dn = 'uuid='+clusterid+',' + CLUSTER_CONFIG_BASEDN
        ret = p_update_to_ldap(dn, list_attr)            
    else:
        strUuid = str(uuid.uuid4())
        newDN = 'uuid='+strUuid+',' + CLUSTER_CONFIG_BASEDN
        attrs = {}
        attrs['objectclass'] = ['CLUSTERCONFIG']
        attrs['hostIPName'] = clusterInfo.hostIp
        attrs['port'] = '80'
        attrs['clusterName'] = clusterInfo.clusterName
        attrs['maxVlan'] = '4095'
        attrs['minVlan'] = '10'
        ret = p_add_to_ldap(newDN, attrs)        
    clc_ip = OpenLdap.get_clc_ip(ldapip)     
    OpenLdap.p_add_service_resource(clc_ip,  clusterInfo.hostIp,thd_SERVICE_TYPE.CLOUD_CC)
    return ret

def p_init_node_info(nodeInfo):
    ret = False
    if nodeInfo==None or nodeInfo.clusterName==None or nodeInfo.hostIp==None:
        return ret
    ldapip, username, password = p_get_ldap_info()
    results = p_get_res_from_ldap(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP='+nodeInfo.hostIp, None)
    if results!=None and results.has_key('IP') > 0:  #update node info
        nodeid = results['uuid'][0]
        list_attr = []
        attr = None 
        attr = (ldap.MOD_REPLACE, 'pcc', nodeInfo.clusterName)
        list_attr.append(attr)
        dn = 'uuid='+nodeid+',' + NODE_CONFIG_BASEDN
        ret = p_update_to_ldap(dn, list_attr)            
    else:
        strUuid = str(uuid.uuid4())
        newDN = 'uuid='+strUuid+',' + NODE_CONFIG_BASEDN
        attrs = {}
        attrs['objectclass'] = ['NODECONFIG']
        attrs['IP'] = nodeInfo.hostIp
        attrs['cn'] = nodeInfo.hostIp
        attrs['pcc'] = nodeInfo.clusterName
        
        if nodeInfo.isLocal!=None and nodeInfo.isLocal:
            attrs['dynamic']='FALSE'
        else:
            attrs['dynamic']='TRUE'
        ret = p_add_to_ldap(newDN, attrs)
        if ret:
            clusterInfo = p_get_clusterinfo_by_cluster(nodeInfo.clusterName)
            if clusterInfo!=None and clusterInfo.hostIp!=None:
                clc_ip = OpenLdap.get_clc_ip(ldapip)    
                OpenLdap.p_regnc_set_cc_global(clusterInfo.hostIp,nodeInfo.hostIp)
                OpenLdap.p_add_service_resource(clc_ip, nodeInfo.hostIp,thd_SERVICE_TYPE.CLOUD_NC)
    return ret


def p_get_node_by_cluster(clusterName):
    if clusterName==None:
        clusterName='any'
    logger.info('p_get_node_by_cluster(%s)' % (clusterName))
    ldapip, username, password = p_get_ldap_info()
    if(clusterName == 'any'):
        return p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'uuid=*')
    else:
        return p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'pcc=' + clusterName)


def _get_clc_ip():
    ldapip, username, password = p_get_ldap_info()
    clcip = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
    return clcip

def p_is_image_used(imageID):
    ret = False
    ldapip, username, password = p_get_ldap_info()   
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for contain in res:
            if contain[0][1].get('ou') != None:
                conname = contain[0][1].get('ou')[0]
                baseDN = 'ou=' + conname + ',' + VM_CONFIG_BASEDN
                configres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'imageId='+imageID, None)
                if len(configres) > 0 and len(configres[0][0][1]) > 0:
                    logger.debug('p_is_image_used:%s' %str(configres))
                    ret = True
    return ret


def p_is_user_has_image(userName):
    ret = False
    imgList = p_euca_get_images_by_user(userName)
    if(len(imgList) > 0):
        for img in imgList:
            if(img.imageCategory == 0):
                ret = True
    return ret

def p_is_user_has_vmconfig(userName):
    ret = False
    vmList = p_get_vmconfigs_by_user(userName)
    if(len(vmList) > 0):
        ret = True
    return ret

class ldapApiHandler:
    def luhya_reg_getClcIp(self, ):
        logger.info('luhya_reg_getClcIp()')
        return _get_clc_ip()

    def luhya_reg_get_clc_host(self,):
        logger.info('luhya_reg_get_clc_host()')
        return _get_clc_ip()

    def luhya_reg_getWalrusIp(self, ):
        logger.info('luhya_reg_getWalrusIp()')
        walrusIp = None
        ldapip, username, password = p_get_ldap_info()
        walrusRes = p_get_res_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'walrusName=walrus', None)
        if walrusRes!=None and walrusRes.has_key('hostIPName') :
            walrusIp = walrusRes['hostIPName'][0]
        return walrusIp

    def luhya_reg_getWalrusPort(self, ):
        walrusPort = None
        ldapip, username, password = p_get_ldap_info()
        walrusRes = p_get_res_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'walrusName=walrus', None)
        if walrusRes!=None and walrusRes.has_key('port'):
            walrusPort = walrusRes['port'][0]
        return walrusPort

    def luhya_reg_getImageList(self, ):
        logger.info('luhya_reg_getImageList')
        return p_get_all_image_list()

    def luhya_reg_getImageInfo(self, imageID):
        logger.info('luhya_reg_getImageInfo')
        imageInfo = None
        if imageID!=None:
            ldapip, username, password = p_get_ldap_info()
            imgList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId=' + imageID)
            if(imgList != None and len(imgList) > 0):
                imageInfo = imgList[0]
        if(imageInfo == None):
            imageInfo = thd_ImageInfo()
        return imageInfo

    def luhya_reg_updateImageInfo(self, imageInfo):
        logger.info('luhya_reg_updateImageInfo')
        return p_updateImageInfo(imageInfo)

    def luhya_reg_addImageInfo(self, newImageInfo):
        logger.info(' luhya_reg_addImageInfo')
        return p_add_image_info(newImageInfo)

    def luhya_reg_init_clc_info(self,clcIp):
        return p_init_clc_info(clcIp)

    def luhya_reg_init_walrus_info(self,walrusIp):
        return p_init_walrus_info(walrusIp)
    
    def luhya_reg_init_cluster_info(self,clusterInfo):
        return p_init_cluster_info(clusterInfo)    
    
    def luhya_reg_init_node_info(self,nodeInfo):
        return p_init_node_info(nodeInfo)    
    
    def luhya_reg_deleteImage(self, imageID):
        logger.info(' luhya_reg_deleteImage()')
        return p_deleteimage(imageID)

    def luhya_reg_is_image_used(self, imageID):
        return p_is_image_used(imageID)

    def luhya_reg_getUserList(self, ):
        logger.info('luhya_reg_getUserList()')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
        return list_info

    def luhya_reg_get_client_user(self, ):
        logger.info('luhya_reg_get_client_user()')
        clientUsers = []
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
        for user in list_info:
            if not user.isAdministrator:
                clientUsers.append(user)
        return clientUsers

    def luhya_reg_get_users_by_department(self, departmentID):
        return p_get_users_by_department(departmentID)


    def luhya_reg_getUserNameList(self, ):
        logger.info('luhya_reg_getUserNameList()')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getUserNameList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
        return list_info

    def luhya_reg_judgeUser(self, userName, password):
        logger.info(' luhya_reg_judgeUser(%s)' % (userName))
        return p_judgeUser(userName, password)

    def luhya_reg_getClusterList(self, ):
        logger.info('luhya_reg_getClusterList()')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getClusterList(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'clusterName=*')
        return list_info

    def luhya_reg_getNodeList(self, ):
        logger.info('luhya_reg_getNodeList()')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'uuid=*')
        return list_info
    
    def luhya_reg_get_ins_report_intv(self,):
        return p_get_ins_report_intv()

    def luhya_reg_getNodeInfoByCluster(self, clusterName):
        return p_get_node_by_cluster(clusterName)

    def luhya_reg_get_local_nodes_by_cluster(self, clusterName):
        nodes = []
        node_list = p_get_node_by_cluster(clusterName)
        for nodeInfo in node_list:
            if nodeInfo.isLocal:
                nodes.append(nodeInfo)
        return nodes

    def luhya_reg_get_remote_nodes_by_cluster(self, clusterName):
        nodes = []
        node_list = p_get_node_by_cluster(clusterName)
        for nodeInfo in node_list:
            if not nodeInfo.isLocal:
                nodes.append(nodeInfo)
        return nodes

    def luhya_reg_getMakeImageNode(self, ):
        logger.info('luhya_reg_getMakeImageNode()')
        ldapip, username, password = p_get_ldap_info()
        nodeId = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'ou=prefrencePrompt', 'MakeImageNode')
        if nodeId == None:
            nodeId = ''
        return nodeId

    def luhya_reg_getWalrusBucketPath(self, ):
        logger.info('luhya_reg_getWalrusBucketPath ')
        ldapip, username, password = p_get_ldap_info()
        buckkit = p_get_value_from_ldap(ldapip, username, password, WALRUS_INFO_BASEDN, 'walrusName=Walrus',
                                        'storageDir')
        return buckkit

    def luhya_reg_getImageXml(self, imageID):
        logger.info('luhya_reg_getImageXml ')
        ldapip, username, password = p_get_ldap_info()
        xml = p_get_value_from_ldap(ldapip, username, password, IMAGE_BASEDN, 'imageId=' + imageID, 'imageLocation')
        return xml

    def luhya_reg_getCategoryList(self, ):
        logger.info('luhya_reg_getCategoryList ')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getCategoryList(ldapip, username, password, DEPARTMENT_BASEDN, 'cn=*')
        return list_info

    def luhya_reg_getImageTypeList(self, ):
        logger.info('luhya_reg_getImageTypeList ')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getImageTypeList(ldapip, username, password, IMAGE_STYLE_BASEDN, 'ImageStyle=*')
        return list_info

    def luhya_reg_getOSTypeList(self, ):
        logger.info('luhya_reg_getOSTypeList ')
        ldapip, username, password = p_get_ldap_info()
        list_info = p_getOSTypeList(ldapip, username, password, OSNAME_BASEDN, 'OSName=*')
        return list_info

    def luhya_reg_getUserSecretKey(self, userName):
        logger.info('luhya_reg_getUserSecretKey ')
        ldapip, username, password = p_get_ldap_info()
        secert = p_get_secert_key(ldapip, username, password, userName)
        return secert

    def luhya_reg_get_user_info(self ,userName):
        userInfo = thd_UserInfo()
        ldapip, username, password = p_get_ldap_info()
        strfil = 'cn='+userName
        list_info = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, strfil)    
        if len(list_info)>0:
            userInfo = copy.deepcopy(list_info[0])
        return userInfo

    def luhya_reg_getUserQueryId(self, userName):
        logger.info('luhya_reg_getUserQueryId ')
        ldapip, username, password = p_get_ldap_info()
        squery = p_get_query_id(ldapip, username, password, userName)
        return squery

    def luhya_reg_getCertificateCode(self, userName):
        ldapip, username, password = p_get_ldap_info()
        return p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'certificateCode')

    def luhya_reg_getMakeImageResource(self, ):
        ldapip, username, password = p_get_ldap_info()
        resTotal = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'ou=prefrencePrompt','MakeImageResource')
        res = 0
        if(resTotal != None):
            res = string.atoi(resTotal)
        else:
            res = 2
        return res


    def euca_reg_getImageList(self, userName):
        return p_euca_get_images_by_user(userName)

    def luhya_reg_get_available_image_list(self, userName):
        imgs = p_luhya_get_available_images_by_user(userName)
        return imgs

    def euca_reg_get_vmconfig(self, vmconfig ):
        logger.info('euca_reg_get_vmconfig()')
        vm = p_euca_get_vmconfig(vmconfig)
        if (vm == None):
            vm = thd_vmConfig()
        return vm

    def euca_reg_domain_user_logon(self, userName, password, domain):
        logger.info('euca_reg_domain_user_logon()')
        ret= p_euca_domain_user_logon(userName, password, domain)
        logger.info('euca_reg_domain_user_logon() end :%d' % ret)
        return ret

    def luhya_reg_get_feature_status(self, featureID ):
        ret = False
        logger.info('luhya_reg_get_feature_status : %s ' % featureID)
        if(featurelist != None):
            featureDic = featurelist[featureID]
            if(featureDic != None):
                if(cmp(featureDic['featureState'].lower(), FEATURE_ON) == 0):
                    ret = True
        return ret

    def luhya_reg_is_support_thermophoresis(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_THERMOPHORESIS)

    def luhya_reg_is_support_remote_usb(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_REMOTE_USB)

    def luhya_reg_is_support_local_usb(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_LOCAL_USB)

    def luhya_reg_is_support_remote_parallel(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_REMOTE_PARALLEL)

    def luhya_reg_is_support_local_parallel(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_LOCAL_PARALLEL)

    def luhya_reg_can_extdisk(self, ):
        return True

    def luhya_reg_can_create_img_from_iso(self, ):
        return p_is_feature_can_use(FEATURE_IMAGE_BY_ISO)

    def luhya_reg_can_create_img_from_p2v(self, ):
        return p_is_feature_can_use(FEATURE_IMAGE_BY_P2V)

    def luhya_reg_support_ad_user(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_AD_USER)

    def luhya_reg_can_snapshot(self, ):
        return p_is_feature_can_use(FEATURE_SUPPORT_SNAPSHOT)

    def euca_reg_change_vmconfig(self, vmconfig):
        logger.info('euca_reg_change_vmconfig() %s' % str(vmconfig))
        return p_change_vmconfig_to_ldap(vmconfig)

    def euca_reg_add_vmconfig(self, vmconfig):
        logger.debug('euca_reg_add_vmconfig add the vmconfig: %s' %str(vmconfig))
        return p_add_vmconfig(vmconfig)

    def euca_reg_delete_vmconfig(self, vmconfig):
        logger.info('euca_reg_delete_vmconfig()')
        return p_delete_vmconfig_from_ldap(vmconfig)

    def euca_reg_delete_vmconfig_by_node(self, nodeIp):
        logger.info('euca_reg_delete_vmconfig_by_node()')
        return p_delete_vmconfig_by_node(nodeIp)

    def euca_reg_get_all_vmconfig(self, ):
        logger.info('euca_reg_get_all_vmconfig()')
        return p_get_all_vmconfig()

    def euca_reg_get_vmconfigs_by_user(self, userName):
        return p_get_vmconfigs_by_user(userName)


    def euca_reg_get_vmconfig_by_node(self, nodeIp ):
        logger.info('euca_reg_get_vmconfig_by_node()')
        return p_get_vmconfig_by_node(nodeIp)

    def euca_reg_get_vmconfig_by_cluster(self, clusterName):
        logger.info('euca_reg_get_vmconfig_by_node()')
        return p_get_vmconfig_by_cluster(clusterName)

    def euca_reg_get_vmconfig_by_id(self, id):
        vm = p_get_vmconfig_by_id(id)
        if(vm == None):
            vm = thd_vmConfig()
        return vm

    def luhya_reg_get_nodeinfo_by_nodeIp(self, nodeIp):
        if(nodeIp != None):
            nodeInfo = p_get_nodeinfo_by_nodeIp(nodeIp)
        if(nodeInfo == None):
            nodeInfo = thd_NodeInfo()
        return nodeInfo

    def luhya_reg_get_clusterinfo_by_cluster(self, clusterName):
        clusterInfo = p_get_clusterinfo_by_cluster(clusterName)
        if(clusterInfo == None):
            clusterInfo = thd_ClusterInfo()
        return clusterInfo


    def luhya_reg_get_department_by_user(self, userName):
        ldapip, username, password = p_get_ldap_info()
        departmentID = -1
        department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'seriesID')
        if(department == None):
            departmentID = -1
        else:
            departmentID = int(department)
        return departmentID

    def luhya_reg_import_user_from_AD(self, domain):
		return p_create_import_AD_user_thread(domain)

    def luhya_reg_add_domain(self, domInfo):
        logger.info('luhya_reg_add_domain()') 
        return p_add_domain_to_ldap(domInfo)

    def luhya_reg_get_all_domains(self ,):
        ldapip, username, password = p_get_ldap_info()
        domainlist = p_euca_get_domain_info(ldapip, username, password, PREFRENCE_BASEDN, 'cn=*')
        return domainlist

    def luhya_reg_get_domain_by_name(self ,domain):
        ldapip, username, password = p_get_ldap_info()
        domainInfo = thd_DomainInfo()
        domainlist = p_euca_get_domain_info(ldapip, username, password, PREFRENCE_BASEDN, 'cn='+domain)
        if len(domainlist)>0 :
            domainInfo = domainlist[0]
        return domainInfo

    def luhya_reg_modify_domain(self, domInfo):
        logger.info('luhya_reg_modify_domain()') 
        return p_modify_domain(domInfo)

    def luhya_reg_del_domain(self, domInfo):
        logger.info('luhya_reg_del_domain()')
        return p_delete_domain_from_ldap(domInfo)

    def luhya_reg_add_user(self, userInfo):
        logger.info('luhya_reg_add_user():%s' %str(userInfo))       
        return p_add_euca_user(userInfo)

    def luhya_reg_modify_user(self, userInfo):
        logger.info('luhya_reg_modify_user() : %s' %str(userInfo))
        ret = False
        if(userInfo.userName == None):
            return ret
        if(not p_euca_is_user_exist(userInfo.userName)):
            return ret
        ret =p_euca_modify_user_info(userInfo)
        return ret

    def luhya_reg_delete_user(self, userName):
        logger.info('luhya_reg_delete_user()')
        ret = 0
        if(userName == None):
            return 0
        if(not p_euca_is_user_exist(userName)):
            return 0
        if p_is_user_has_image(userName):
            logger.info('%s has private image' %userName)
            ret = -1
        if p_is_user_has_vmconfig(userName):
            logger.info('%s has vmconfig' %userName)
            ret = -2
        if ret ==0:    
            if p_euca_del_user_info(userName):
                ret = 0
            else:
                ret = -3
#        p_del_vmconfig_by_user(userName)
#        p_del_image_by_user(userName)
        return ret

    def luhya_reg_add_department(self, department):
        logger.info('luhya_reg_add_department()')
        if(department == None):
            return False
        return p_euca_add_department(department)

    def luhya_reg_delete_department(self, department):
        logger.info('luhya_reg_delete_department()')
        ret = False
        if(department == None):
            return ret  
        if(p_department_can_be_delete(department)):
            p_euca_del_department(department)
        return True

    def luhya_reg_department_can_be_delete(self, preDepartment):
        logger.info('luhya_reg_department_can_be_delete()')
        ret = p_department_can_be_delete(preDepartment)
        return ret

    def luhya_reg_is_admin(self , userName):
		return p_euca_is_admin(userName)
    
    def luhya_reg_get_current_resource(self):     #start booth li
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

		
    def luhya_reg_get_node_migrate_list(self ,):
        logger.info('luhya_reg_get_node_migrate_list()')
        return p_get_node_migrate_list()
    
    def luhya_reg_delete_node_migrate_pair(self , sourceIP , targetIP):
        logger.info('luhya_reg_delete_node_migrate_pair() %s: '% sourceIP+' ,'+ targetIP)
        return p_delete_node_migrate_pair(sourceIP, targetIP)

    def luhya_reg_get_services_by_ip(self, ipAddress):
        return p_get_services_by_ip(ipAddress)
    
    def luhya_reg_get_all_service_ip(self,):
        return p_get_all_service_ip()

    def luhya_reg_is_service_start(self,):
        return p_is_service_start()
 
    def luhya_reg_start_service(self, ):
        return p_start_service()
    
    def luhya_reg_stop_service(self, ):
        return p_stop_service()

    def luhya_reg_add_node_migrate_pair(self , sourceIP , targetIP):
        logger.info('luhya_reg_add_node_migrate_pair() %s: ' % sourceIP+' ,' +targetIP)
        return p_add_node_migrate_pair(sourceIP, targetIP)
    
    def luhya_reg_get_migrate_Info_list(self , user):
        logger.info('luhya_reg_get_migrate_Info_list() %s: ' % user)
        return p_get_migrate_Info_list(user)
    
    def luhya_reg_get_available_snapshot_num(self,userName,imageID):
        logger.info('luhya_reg_get_available_snapshot_num()')
        return p_get_available_snapshot_num(userName,imageID)
    
    def luhya_reg_get_current_snapshot_id(self,userName,imageID):
        logger.info('luhya_reg_get_current_snapshot_id()')
        return p_get_current_snapshot_id(userName,imageID)


    def luhya_reg_set_current_snapshot_id(self,userName,imageID,snapshotID):
        logger.info('luhya_reg_set_current_snapshot_id()')
        return p_set_current_snapshot_id(userName,imageID,snapshotID)
  
    def luhya_reg_get_snapshot_list(self,userName,imageID):
        logger.info('luhya_reg_get_snapshot_list()')
        return p_get_snapshot_list(userName,imageID)
 
    def luhya_reg_get_snapshotInfo_by_id(self,userName,imageID,snapshotID):
        logger.info('luhya_reg_get_snapshotInfo_by_id()')
        return p_get_snapshotInfo_by_id(userName,imageID,snapshotID) 
           
    def luhya_reg_add_snapshot(self,snapshotInfo):
        logger.info('luhya_reg_add_snapshot() %s'%snapshotInfo)
        return p_add_snapshot(snapshotInfo)
        
    def luhya_reg_modify_snapshot(self,snapshotInfo):
        logger.info('luhya_reg_modify_snapshot() %s'%snapshotInfo)
        return p_modify_snapshot(snapshotInfo) 
          
    def luhya_reg_delete_snapshot(self,userName,imageID,snapshotID):
        logger.info('luhya_reg_delete_snapshot()')
        return p_delete_snapshot(userName,imageID,snapshotID)
        
    def luhya_reg_get_available_snapshot_id(self,userName,imageID):
        logger.info('luhya_reg_get_available_snapshot_id()')
        return p_get_available_snapshot_id(userName,imageID)

    def luhya_reg_set_make_image_node(self , nodeIp):
        return p_set_make_image_node(nodeIp)

    def luhya_reg_get_max_private_instances(self , user):
        return p_get_max_private_instances(user)      
        

    def luhya_reg_get_clusterInfo_by_ccIp(self,ccIp):
        clusterInfo = None
        if(ccIp != None):
            clusterInfo = p_get_clusterInfo_by_clusterIp(ccIp)
        if clusterInfo==None:
            clusterInfo = thd_ClusterInfo()
        return clusterInfo    

    def luhya_reg_is_registered(self ,servID,hostIp):
        return p_is_registered(servID,hostIp)
     
    def luhya_reg_is_online(self,):
        return True
   
# g_LdapThriftServer_main_interface,LdapThriftServer main interface, starting point 
class g_LdapThriftServer_main_interface(threading.Thread):
    "g_LdapThriftServer_main_interface"

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        logger.info('g_LdapThriftServer_main_interface running ...')
        p_euca_reg_get_feature_switch()
        
        handler = ldapApiHandler()
        processor = ldapApi.Processor(handler)
        transport = TSocket.TServerSocket(utility.get_local_publicip(), thd_port.THRIFT_LDAP_PORT)
        tfactory = TTransport.TBufferedTransportFactory()
        pfactory = TBinaryProtocol.TBinaryProtocolFactory()

        #server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

        # You could do one of these for a multithreaded server
        #server = TServer.TThreadedServer(processor, transport, tfactory, pfactory)
        server = TServer.TThreadPoolServer(processor, transport, tfactory, pfactory)

        logger.info('Starting the server...')
        server.serve()
        logger.error('thrift server quit!')


    # LdapThriftServerexternal interface


def preInit (user_data):
    logger.info('pre_init starting ...')
    p_get_global_ip()
    getClcIp = p_get_clc_ip_thread()
    getClcIp.start()
    getSourceThread = p_get_server_source_thread()
    getSourceThread.start()    
    LdapThriftServer_main = g_LdapThriftServer_main_interface()
    LdapThriftServer_main.start()
    
    hdSourceThread = p_transmit_server_source_thread()
    hdSourceThread.start()
    heartBeatThread = p_heart_beat_thread()
    heartBeatThread.start()
        
    log_string = 'started g_LdapThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string)
    return 0     #sys.exit()


def postInit (user_data):
    pass
