#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from cloudbot.proxyinterface import ldapApi
from cloudbot.proxyinterface.ttypes import *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from cloudbot.utils import OpenLdap,utility
from cloudbot.utils.const_def import *

import os,copy
import time,hashlib
import threading
import xml.dom.minidom
import codecs

g_online = False
g_online_switch = threading.Lock()
logger = utility.init_log()

def _is_online():
    global g_online
    b_online = copy.deepcopy(g_online)
    return b_online

def _save_user_info(userInfo):
    user_path = USER_ROOT+userInfo.userName+'/'
    if not os.path.exists(user_path):
        try:
            os.makedirs(user_path)
        except:
            logger.error('Create ' + user_path + ' error!')
            return False
    impl = xml.dom.minidom.getDOMImplementation()
    dom=impl.createDocument(None,'userInfo',None)
    root = dom.documentElement
    text=unicode(userInfo.userName,'utf8')
    item = utility.make_easy_tag(dom,'userName',text)
    root.appendChild(item)
    text= unicode(userInfo.sLogonName,'utf8')
    item = utility.make_easy_tag(dom,'sLogonName',text)
    root.appendChild(item)
    text = unicode(userInfo.bCryptedPassword,'utf8')
    item = utility.make_easy_tag(dom,'bCryptedPassword',text)
    root.appendChild(item)
    if userInfo.domain!=None:
        text = unicode(userInfo.domain,'utf8')
        item = utility.make_easy_tag(dom,'domain',text)
        root.appendChild(item)

    user_info_file = user_path+USER_LOGON_FILE
    utility.write_xml_file(dom,user_info_file)
    return True

def _get_user_info(user_info_file):
    user_info = thd_UserInfo()
    if os.path.exists(user_info_file):
        dom = xml.dom.minidom.parse(user_info_file)
        root = dom.documentElement
        el = dom.childNodes
        for clientNode in el:
            nodelist = clientNode.childNodes
            for node in nodelist:
                if 'userName'==node.nodeName:
                    user_info.userName = node.childNodes[0].nodeValue.encode('utf8')
                elif 'bCryptedPassword' ==node.nodeName:
                    user_info.bCryptedPassword = node.childNodes[0].nodeValue.encode('utf8')
                elif 'sLogonName'==node.nodeName:
                    user_info.sLogonName = node.childNodes[0].nodeValue.encode('utf8')
                elif 'domain'==node.nodeName:
                    user_info.domain = node.childNodes[0].nodeValue.encode('utf8')
    logger.debug('_get_user_info user_info:%s' %str(user_info))
    return user_info

def _save_cluster_info(clusterInfo):
    if not os.path.exists(LDAP_CACHE_ROOT):
        try:
            os.makedirs(LDAP_CACHE_ROOT)
        except:
            logger.error('Create ' + LDAP_CACHE_ROOT + ' error!')
            return False
    impl = xml.dom.minidom.getDOMImplementation()
    dom=impl.createDocument(None,'cluster',None)
    root = dom.documentElement
    text= unicode(clusterInfo.clusterName,'utf8')
    item = utility.make_easy_tag(dom,'clusterName',text)
    root.appendChild(item)
    text = unicode(clusterInfo.hostIp,'utf8')
    item = utility.make_easy_tag(dom,'hostIp',text)
    root.appendChild(item)
    if clusterInfo.HYPERVISOR!=None:
        text = unicode(clusterInfo.HYPERVISOR,'utf8')
        item = utility.make_easy_tag(dom,'HYPERVISOR',text)
        root.appendChild(item)

    utility.write_xml_file(dom,CLUSTER_INFO_FILE)
    return True

def _get_cluster_info():
    clusterInfo = thd_ClusterInfo()
    if os.path.exists(CLUSTER_INFO_FILE):
        dom = xml.dom.minidom.parse(CLUSTER_INFO_FILE)
        root = dom.documentElement
        el = dom.childNodes
        for clientNode in el:
            nodelist = clientNode.childNodes
            for node in nodelist:
                if 'hostIp'==node.nodeName:
                    clusterInfo.hostIp = node.childNodes[0].nodeValue.encode('utf8')
                elif 'HYPERVISOR' ==node.nodeName:
                    clusterInfo.HYPERVISOR = node.childNodes[0].nodeValue.encode('utf8')
                elif 'clusterName'==node.nodeName:
                    clusterInfo.clusterName = node.childNodes[0].nodeValue.encode('utf8')
    return clusterInfo


def _save_node_info(nodeInfo):
    if not os.path.exists(LDAP_CACHE_ROOT):
        try:
            os.makedirs(LDAP_CACHE_ROOT)
        except:
            logger.error('Create ' + LDAP_CACHE_ROOT + ' error!')
            return False
    impl = xml.dom.minidom.getDOMImplementation()
    dom=impl.createDocument(None,'node',None)
    root = dom.documentElement
    text = unicode(nodeInfo.hostIp,'utf8')
    item = utility.make_easy_tag(dom,'hostIp',text)
    root.appendChild(item)    
    text= unicode(nodeInfo.clusterName,'utf8')
    item = utility.make_easy_tag(dom,'clusterName',text)
    root.appendChild(item)   
    if nodeInfo.isLocal:
        text = 'TRUE'
    else:
        text = 'FALSE'
    item = utility.make_easy_tag(dom,'isLocal',text)
    root.appendChild(item)

    utility.write_xml_file(dom,NODE_INFO_FILE)
    return True

def _get_node_info():
    nodeInfo = thd_NodeInfo()
    logger.info('_get_node_info node file:%s ' %NODE_INFO_FILE)
    if os.path.exists(NODE_INFO_FILE):
        dom = xml.dom.minidom.parse(NODE_INFO_FILE)
        root = dom.documentElement
        el = dom.childNodes
        for clientNode in el:
            nodelist = clientNode.childNodes
            for node in nodelist:
                logger.info('_get_node_info : %s' %node.nodeName)
                if 'hostIp'==node.nodeName:
                    nodeInfo.hostIp = node.childNodes[0].nodeValue.encode('utf8')
                elif 'isLocal' ==node.nodeName:
                    if 'TRUE'==node.childNodes[0].nodeValue:
                        nodeInfo.isLocal=True
                    else:
                        nodeInfo.isLocal=False
                elif 'clusterName'==node.nodeName:
                    nodeInfo.clusterName = node.childNodes[0].nodeValue.encode('utf8')
    return nodeInfo



def _save_walrus_info(walrusIp,port):
    if not os.path.exists(LDAP_CACHE_ROOT):
        try:
            os.makedirs(LDAP_CACHE_ROOT)
        except:
            logger.error('Create ' + LDAP_CACHE_ROOT + ' error!')
            return False
    impl = xml.dom.minidom.getDOMImplementation()
    dom=impl.createDocument(None,'walrus',None)
    root = dom.documentElement
    text=walrusIp
    item = utility.make_easy_tag(dom,'ip',text)
    root.appendChild(item)
    text = port
    item = utility.make_easy_tag(dom,'port',text)
    root.appendChild(item)

    utility.write_xml_file(dom,WALRUS_INFO_FILE)
    return True          
     
def _get_walrus_ip():
    host_ip = None
    logger.info('walrus ip file:%s' %WALRUS_INFO_FILE)
    if os.path.exists(WALRUS_INFO_FILE):
        dom = xml.dom.minidom.parse(WALRUS_INFO_FILE)
        root = dom.documentElement
        el = dom.childNodes
        for clientNode in el:
            nodelist = clientNode.childNodes
            for client in nodelist:
                if 'ip'==client.nodeName:
                    host_ip = client.childNodes[0].nodeValue
                    break
    return host_ip

def _get_walrus_port():
    s_port = None
    if os.path.exists(WALRUS_INFO_FILE):
        dom = xml.dom.minidom.parse(WALRUS_INFO_FILE)
        root = dom.documentElement
        el = dom.childNodes
        for clientNode in el:
            nodelist = clientNode.childNodes
            for client in nodelist:
                if 'port'==client.nodeName:
                    s_port = client.childNodes[0].nodeValue
                    break
    return s_port

def _save_clc_ip(clc_ip):  
    if not os.path.exists(LDAP_CACHE_ROOT):
        try:
            os.makedirs(LDAP_CACHE_ROOT)
        except:
            logger.error('Create ' + LDAP_CACHE_ROOT + ' error!')
            return False
    
    #delete old file
    utility.remove_file(CLC_INFO_FILE)
    #create new xml
    impl = xml.dom.minidom.getDOMImplementation()
    dom=impl.createDocument(None,'clcinfo',None)
    root = dom.documentElement
    item = utility.make_easy_tag(dom,'ip',clc_ip)
    root.appendChild(item)       
    #write to cache file
    utility.write_xml_file(dom, CLC_INFO_FILE)
    return True

def p_get_clc_ip():
    clc_ip  = None
    if _is_online():
        ldap_ip = utility.get_real_ldap()
        if ldap_ip!=None:
            clc_ip = OpenLdap.get_clc_ip(ldap_ip)
            if clc_ip != None:
                _save_clc_ip(clc_ip)
            else:
                logger.debug('get clc ip is error!')
        else:
            logger.debug('get real ldap ip is error!')           
    else:
        clc_ip = _get_clc_ip_from_xml()
    return clc_ip

def _get_clc_ip_from_xml():
    clc_ip = None
    if os.path.exists(CLC_INFO_FILE):
        dom = xml.dom.minidom.parse(CLC_INFO_FILE)
        root = dom.documentElement
        for node in root.childNodes:
            if (node.nodeName == "ip"):
                clc_ip = node.childNodes[0].nodeValue
    else:
        logger.debug('file %s is not exisit!' %CLC_INFO_FILE)
    return clc_ip


class ldapApiHandler:
    def luhya_reg_getClcIp(self, ):
        ''' harrison
        如果是在线模式：
           1)转发调用LdapThriftServer API luhya_reg_getClcIp( )获取
           2)将获取的clc ip保存在: /var/lib/eucalyptus/.luhya/ldapcaches/clc.ini中
        如果是离线模式：
           从/var/lib/eucalyptus/.luhya/ldapcaches/clc.ini读取clc ip
        注：
        clc.in中clc ip保存格式如下：
            clc_ip=192.168.99.100    
        '''
        return p_get_clc_ip()        

    def luhya_reg_get_clc_host(self,):
        return utility.get_local_publicip()

    def luhya_reg_getWalrusIp(self, ):
        '''  nyeo
        调用_is_online()判断本机是否在线:
        如果在线：
             调用真正ldap的luhya_reg_getWalrusIp ()获得walrus的port，并保存到/var/lib/eucalyptus/.luhya/ldapCache/的walrus.ini中
             返回walrus的ip
        如果不在线：
            查看/var/lib/eucalyptus/.luhya/ldapCache/是否有walrus.ini文件，如果有：
                 从walrus.ini中取得walrus的ip返回
             如果没有：
                 返回None        
        '''        
        walrusIp = None
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                logger.debug('the real ldap ip:%s' %ldap_ip)
                walrusIp,port = OpenLdap.get_walrus_info(ldap_ip)
                _save_walrus_info(walrusIp,port)
            else:
                logger.debug('get the real ldap ip is error!' )
        else:
            if os.path.exists(WALRUS_INFO_FILE):
                walrusIp = _get_walrus_ip()
            else:
                logger.debug('file %s is not exisit!' %WALRUS_INFO_FILE )
        return walrusIp

    def luhya_reg_getWalrusPort(self, ):
        '''  nyeo
        调用_is_online()判断本机是否在线:
        如果在线：
             调用真正ldap的luhya_reg_getWalrusPort ()获得walrus的port，并保存到/var/lib/eucalyptus/.luhya/ldapCache/的walrus.ini中
             返回walrus的port
        如果不在线：
            查看/var/lib/eucalyptus/.luhya/ldapCache/是否有walrus.ini文件，如果有：
                 从walrus.ini中取得walrus的port返回
             如果没有：
                 返回None        
        '''       
        s_port = None
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                walrusIp,s_port = OpenLdap.get_walrus_info(ldap_ip)
            else:
                logger.debug('get the real ldap ip is error!' )
        else:
            if os.path.exists(WALRUS_INFO_FILE):
                s_port = _get_walrus_port()
            else:
                logger.debug('file %s is not exisit!' %WALRUS_INFO_FILE )
        return s_port        
        
    def luhya_reg_getImageInfo(self, imageID):
        '''   harrison
        在线模式：
             直接调用LdapThriftServer API luhya_reg_getImageInfo(imageID)返回镜像列表信息，并
        将镜像列表保存在
             /var/lib/eucalyptus/.luhya/caches/imageID/imageinfo.ini中，imageinfo.ini内>容如下：
                 imageId=emi-123456
                 name=开发部XP
                 …
        离线模式：
             从/var/lib/eucalyptus/.luhya/caches/imageID/imageinfo.ini获取镜像列表信息
        '''        
        image_info = thd_ImageInfo()
        image_info_file = IMAGE_CACHE_ROOT + imageID + "/" + IMAGE_INFO_FILE
        image_cache = IMAGE_CACHE_ROOT + imageID + "/"


        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                logger.info('real ldap :%s' %ldap_ip)
                image_info = OpenLdap.get_image_info(ldap_ip,imageID)
            
                if image_info != None and image_info.imageId!=None:
                    if not os.path.exists(image_cache):
                        try:
                            os.makedirs(image_cache)
                        except:
                            logger.error('Create ' + image_cache + ' error!')
                            return image_info
                    #delete old cache file
                    utility.remove_file(image_info_file)
                    #create new xml
                    impl = xml.dom.minidom.getDOMImplementation()
                    dom=impl.createDocument(None,'imageinfo',None)
                    root = dom.documentElement				
                    item = utility.make_easy_tag(dom,'imageId',image_info.imageId)
                    root.appendChild(item)       
                    if image_info.imageLocation!=None:             
                        item = utility.make_easy_tag(dom,'imageLocation',unicode(image_info.imageLocation,'utf8'))
                        root.appendChild(item)       
                    if image_info.imageState!=None:
                        item = utility.make_easy_tag(dom,'imageState',image_info.imageState)
                        root.appendChild(item)       
                    if image_info.imageOwnerId!=None:
                        item = utility.make_easy_tag(dom,'imageOwnerId',image_info.imageOwnerId)
                        root.appendChild(item)       
                    if image_info.architecture!=None:
                        item = utility.make_easy_tag(dom,'architecture',unicode(image_info.architecture,'utf8'))
                        root.appendChild(item)       
                    if image_info.imageType!=None:
                        item = utility.make_easy_tag(dom,'imageType',unicode(image_info.imageType,'utf8'))
                        root.appendChild(item)       
                    if image_info.kernelId!=None:
                        item = utility.make_easy_tag(dom,'kernelId',image_info.kernelId)
                        root.appendChild(item)       
                    if image_info.ramdiskId!=None:
                        item = utility.make_easy_tag(dom,'ramdiskId',image_info.ramdiskId)
                        root.appendChild(item)       
                    if image_info.isPublic!=None:
                        text = None
                        if image_info.isPublic:
                            text = 'TRUE'
                        else:
                            text = 'FALSE'
                        item = utility.make_easy_tag(dom,'isPublic',text)
                        root.appendChild(item)       
                    if image_info.signature!=None:
                        item = utility.make_easy_tag(dom,'signature',image_info.signature)
                        root.appendChild(item)       
                    if image_info.name!=None:
                        item = utility.make_easy_tag(dom,'name',unicode(image_info.name,'utf8'))
                        root.appendChild(item)       
                    if image_info.imageCategory!=None:
                        item = utility.make_easy_tag(dom,'imageCategory',str(image_info.imageCategory))
                        root.appendChild(item)       
                    if image_info.description!=None:
                        item = utility.make_easy_tag(dom,'description',unicode(image_info.description,'utf8'))
                        root.appendChild(item)       
                    if image_info.platform!=None:
                        item = utility.make_easy_tag(dom,'platform',image_info.platform)
                        root.appendChild(item)       
                    if image_info.ownerName!=None:
                        item = utility.make_easy_tag(dom,'ownerName',unicode(image_info.ownerName,'utf8'))
                        root.appendChild(item)       
                    if image_info.vmStyle!=None:
                        item = utility.make_easy_tag(dom,'vmStyle',image_info.vmStyle)
                        root.appendChild(item)       
                    if image_info.Groups!=None:
                        item = utility.make_easy_tag(dom,'Groups',image_info.Groups)
                        root.appendChild(item)       
                    if image_info.OS!=None:
                        item = utility.make_easy_tag(dom,'OS',image_info.OS)
                        root.appendChild(item)       
                    if image_info.createTime!=None:
                        item = utility.make_easy_tag(dom,'createTime',image_info.createTime)
                        root.appendChild(item)       
                    if image_info.size!=None:
                        item = utility.make_easy_tag(dom,'size',str(image_info.size))
                        root.appendChild(item)       
                    if image_info.manifest!=None:
                        item = utility.make_easy_tag(dom,'manifest',image_info.manifest)
                        root.appendChild(item)       
                    if image_info.HYPERVISOR!=None:
                        item = utility.make_easy_tag(dom,'HYPERVISOR',unicode(image_info.HYPERVISOR,'utf8'))
                        root.appendChild(item)       				
                    #write to cache file
                    utility.write_xml_file(dom,image_info_file)
                else:
                    logger.debug('get image %s is error!' %imageID)
            else:
                logger.debug('get the real ldap ip is error!' )
        else:
            if os.path.exists(image_info_file):
                dom = xml.dom.minidom.parse(image_info_file)
                root = dom.documentElement
                for node in root.childNodes:
                    if (node.nodeName == "imageId"):
                        image_info.imageId = node.childNodes[0].nodeValue						
                    elif (node.nodeName == "imageLocation"):
                        image_info.imageLocation = node.childNodes[0].nodeValue.encode('utf8')                   
                    elif (node.nodeName == "imageState"):
                        image_info.imageState = node.childNodes[0].nodeValue                    
                    elif (node.nodeName == "imageOwnerId"):
                        image_info.imageOwnerId = node.childNodes[0].nodeValue
                    elif (node.nodeName == "architecture"):
                        image_info.architecture = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "imageType"):
                        image_info.imageType = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "kernelId"):
                        image_info.kernelId = node.childNodes[0].nodeValue
                    elif (node.nodeName == "ramdiskId"):
                        image_info.ramdiskId = node.childNodes[0].nodeValue
                    elif (node.nodeName == "isPublic"):
                        if node.childNodes[0].nodeValue=='TRUE':
                            image_info.isPublic = True
                        else:
                            image_info.isPublic = False
                    elif (node.nodeName == "signature"):
                        image_info.signature = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "name"):
                        image_info.name = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "imageCategory"):
                        image_info.imageCategory = int(node.childNodes[0].nodeValue)
                    elif (node.nodeName == "description"):
                        image_info.description = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "platform"):
                        image_info.platform = node.childNodes[0].nodeValue
                    elif (node.nodeName == "ownerName"):
                        image_info.ownerName = node.childNodes[0].nodeValue.encode('utf8')
                    elif (node.nodeName == "vmStyle"):
                        image_info.vmStyle = node.childNodes[0].nodeValue
                    elif (node.nodeName == "Groups"):
                        image_info.Groups = node.childNodes[0].nodeValue
                    elif (node.nodeName == "OS"):
                        image_info.OS = node.childNodes[0].nodeValue
                    elif (node.nodeName == "createTime"):
                        image_info.createTime = node.childNodes[0].nodeValue
                    elif (node.nodeName == "size"):
                        image_info.size = int(node.childNodes[0].nodeValue)
                    elif (node.nodeName == "manifest"):
                        image_info.manifest = node.childNodes[0].nodeValue
                    elif (node.nodeName == "HYPERVISOR"):
                        image_info.HYPERVISOR = node.childNodes[0].nodeValue.encode('utf8')
            else:
                logger.debug('image info file %s is not exisit!' %image_info_file)
        return image_info                
   
    
    def luhya_reg_init_node_info(self,nodeInfo):
        '''   nyeo
        调用 is_online()判断本机是否在线
        如果在线：
            1、将nodeInfo的isLocal属性设为TRUE
            2、调用真正的ldap的接口luhya_reg_init_node_info(nodeInfo)
            3、如果注册成功：
                1、将nodeInfo、clusterInfo保存到local_node.ini cluster.ini中
                2、返回TRUE
            如果注册不成功：
                返回FALSE
        如果不在线：
            返回FALSE
        '''
        ret = False
        if _is_online():
            nodeInfo.isLocal = True
            ldap_ip = utility.get_real_ldap()
            logger.info('real ldap:%s' %ldap_ip)
            if ldap_ip!=None:
                ret = OpenLdap.p_register_node(ldap_ip,nodeInfo)
                if ret:
                    _save_node_info(nodeInfo)
                    clusterInfo = OpenLdap.get_clusterinfo_by_cluster(ldap_ip,nodeInfo.clusterName)
                    logger.info('cluster info:%s' %str(clusterInfo))
                    _save_cluster_info(clusterInfo)
                else:
                    logger.debug('register node %s is error!' %str(nodeInfo))
            else:
                logger.debug('get real ldap ip is error')
        return ret
    
    def luhya_reg_get_ins_report_intv(self,):
        '''   nyeo
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_ins_report_intv ()获得时间间隔
        如果不在线：
            返回 1
        '''
        ret = 1
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                ret = OpenLdap.p_get_ins_report_intv(ldap_ip) 
            else:
                logger.debug('get real ldap ip is error')       
        return ret

    def luhya_reg_getCategoryList(self, ):
        '''  harrison
        在线模式：
            直接调用LdapThriftServer API luhya_reg_getCategoryList
            获取部门列表信息，并保存在
            /var/lib/eucalyptus/.luhya/ldapcaches/categories.ini
            categories内容如下：
                 category0=公有镜像
                 category1=私有镜像
                 category1001=开发部
                 category1002=测试部
                 category1003=行政部
        离线模式：
            从/var/lib/eucalyptus/.luhya/ldapcaches/categories.in获取部门列表        
        '''   
        category_list = []
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                category_list = OpenLdap.get_category_list(ldap_ip)
                if(len(category_list)>0):
                    #rm old cache file
                    utility.remove_file(CATEGORIES_INFO_FILE)
                    #create new xml
                    logger.info('category_list : %s' %str(category_list))
                    impl = xml.dom.minidom.getDOMImplementation()
                    dom=impl.createDocument(None,'categories',None)
                    root = dom.documentElement
                    for category in category_list:
                        uncategory=unicode(category,'utf8')
                        item = utility.make_easy_tag(dom,'category',uncategory)
                        root.appendChild(item)       
                        #write to cache file
                        utility.write_xml_file(dom, CATEGORIES_INFO_FILE)
            else:
                logger.debug('get real ldap ip is error')
        else:
            if (os.path.exists(CATEGORIES_INFO_FILE)):
                dom = xml.dom.minidom.parse(CATEGORIES_INFO_FILE)
                root = dom.documentElement
                for node in root.childNodes:
                    svalue =node.childNodes[0].nodeValue
                    category_list.append(svalue.encode('utf8'))
            else:
                logger.debug('file: %s is not exisit!' %CATEGORIES_INFO_FILE)
            logger.info('category_list : %s' %str(category_list))
        return category_list

    def euca_reg_getImageList(self, userName):
        ''' harrison
        proxcyLdap上实现euca_reg_getImageList(userName)
	list<thd_ImageInfo> euca_reg_getImageList(userName);
	在线模式：
	 直接调用LdapThriftServer API euca_reg_getImageList(userName)返回
	镜像列表信息，并将镜像列表保存在
	/var/lib/eucalyptus/.luhya/users/userName/imageinfos.xml中，
	imageinfos.xml内容如下：
	< emi-123456>
	   <name>开发部XP</name>
	   <imageState>avalible</imageState>
	   <platform>windows</platform>
	   …
	</emi-123456>
	…
	离线模式：
	从/var/lib/eucalyptus/.luhya/users/imageinfos.xml
	获取镜像列表信息     
        '''
        image_list = []
        image_list_file = USER_ROOT + userName + "/" + USER_IMAGES_INFO_FILE
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None: 
                image_list = OpenLdap.p_get_images_by_user(ldap_ip,userName)
                if(len(image_list)>0):
                    #create new xml
                    impl = xml.dom.minidom.getDOMImplementation()
                    dom=impl.createDocument(None,'image_infos',None)
                    root = dom.documentElement
                    for image_info in image_list:
                        sub_element = utility.make_easy_tag(dom,'image_info','')				

                        item = utility.make_easy_tag(dom,'imageId',image_info.imageId)
                        sub_element.appendChild(item)       

                        if image_info.imageLocation!=None:
                            item = utility.make_easy_tag(dom,'imageLocation',unicode(image_info.imageLocation,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.imageState!=None:
                            item = utility.make_easy_tag(dom,'imageState',image_info.imageState)
                            sub_element.appendChild(item)       
                        if image_info.imageOwnerId!=None:
                            item = utility.make_easy_tag(dom,'imageOwnerId',image_info.imageOwnerId)
                            sub_element.appendChild(item)       
                        if image_info.architecture!=None:
                            item = utility.make_easy_tag(dom,'architecture',unicode(image_info.architecture,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.imageType!=None:
                            item = utility.make_easy_tag(dom,'imageType',image_info.imageType)
                            sub_element.appendChild(item)       
                        if image_info.kernelId!=None:
                            item = utility.make_easy_tag(dom,'kernelId',image_info.kernelId)
                            sub_element.appendChild(item)       
                        if image_info.ramdiskId!=None:
                            item = utility.make_easy_tag(dom,'ramdiskId',image_info.ramdiskId)
                            sub_element.appendChild(item)       
                        if image_info.isPublic!=None:
                            text = None
                            if image_info.isPublic:
                                text = 'TRUE'
                            else:
                                text = 'FALSE'
                            item = utility.make_easy_tag(dom,'isPublic',text)
                            sub_element.appendChild(item)       
                        if image_info.signature!=None:
                            item = utility.make_easy_tag(dom,'signature',unicode(image_info.signature,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.name!=None:
                            item = utility.make_easy_tag(dom,'name',unicode(image_info.name,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.imageCategory!=None:
                            item = utility.make_easy_tag(dom,'imageCategory',str(image_info.imageCategory))
                            sub_element.appendChild(item)       
                        if image_info.description!=None:
                            item = utility.make_easy_tag(dom,'description',unicode(image_info.description,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.platform!=None:
                            item = utility.make_easy_tag(dom,'platform',image_info.platform)
                            sub_element.appendChild(item)       
                        if image_info.ownerName!=None:
                            item = utility.make_easy_tag(dom,'ownerName',unicode(image_info.ownerName,'utf8'))
                            sub_element.appendChild(item)       
                        if image_info.vmStyle!=None:
                            item = utility.make_easy_tag(dom,'vmStyle',image_info.vmStyle)
                            sub_element.appendChild(item)       
                        if image_info.Groups!=None:
                            item = utility.make_easy_tag(dom,'Groups',image_info.Groups)
                            sub_element.appendChild(item)       
                        if image_info.OS!=None:
                            item = utility.make_easy_tag(dom,'OS',image_info.OS)
                            sub_element.appendChild(item)       
                        if image_info.createTime!=None:
                            item = utility.make_easy_tag(dom,'createTime',image_info.createTime)
                            sub_element.appendChild(item)       
                        if image_info.size!=None:
                            item = utility.make_easy_tag(dom,'size',str(image_info.size))
                            sub_element.appendChild(item)       
                        if image_info.manifest!=None:
                            item = utility.make_easy_tag(dom,'manifest',image_info.manifest)
                            sub_element.appendChild(item)       
                        if image_info.HYPERVISOR!=None:
                            item = utility.make_easy_tag(dom,'HYPERVISOR',unicode(image_info.HYPERVISOR,'utf8'))
                            sub_element.appendChild(item)       

                        root.appendChild(sub_element)       
                    #write to cache file
                    utility.remove_file(image_list_file)
                    utility.write_xml_file(dom, image_list_file)
            else:
                logger.debug('get real ldap ip is error!')
        else:
            if(os.path.exists(image_list_file)):
                dom = xml.dom.minidom.parse(image_list_file)
                root = dom.documentElement
                for node in root.childNodes:
                    if(node.nodeName == "image_info"):		                
                        image_info = thd_ImageInfo()
                        for sub_node in node.childNodes:                                					
                            if (sub_node.nodeName == "imageId"):
                                image_info.imageId = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "imageLocation"):
                                image_info.imageLocation = sub_node.childNodes[0].nodeValue.encode('utf8')                    
                            elif (sub_node.nodeName == "imageState"):
                                image_info.imageState = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "imageOwnerId"):
                                image_info.imageOwnerId = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "architecture"):
                                image_info.architecture = sub_node.childNodes[0].nodeValue.encode('utf8')
                            elif (sub_node.nodeName == "imageType"):
                                image_info.imageType = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "kernelId"):
                                image_info.kernelId = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "ramdiskId"):
                                image_info.ramdiskId = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "isPublic"):
                                if sub_node.childNodes[0].nodeValue=='TRUE':
                                    image_info.isPublic = True
                                else:
                                    image_info.isPublic = False
                            elif (sub_node.nodeName == "signature"):
                                image_info.signature = sub_node.childNodes[0].nodeValue.encode('utf8')
                            elif (sub_node.nodeName == "name"):
                                image_info.name = sub_node.childNodes[0].nodeValue.encode('utf8')
                            elif (sub_node.nodeName == "imageCategory"):
                                image_info.imageCategory = int(sub_node.childNodes[0].nodeValue)
                            elif (sub_node.nodeName == "description"):
                                image_info.description = sub_node.childNodes[0].nodeValue.encode('utf8')
                            elif (sub_node.nodeName == "platform"):
                                image_info.platform = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "ownerName"):
                                image_info.ownerName = sub_node.childNodes[0].nodeValue.encode('utf8')
                            elif (sub_node.nodeName == "vmStyle"):
                                image_info.vmStyle = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "Groups"):
                                image_info.Groups = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "OS"):
                                image_info.OS = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "createTime"):
                                image_info.createTime = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "size"):
                                image_info.size = int(sub_node.childNodes[0].nodeValue)
                            elif (sub_node.nodeName == "manifest"):
                                image_info.manifest = sub_node.childNodes[0].nodeValue
                            elif (sub_node.nodeName == "HYPERVISOR"):
                                image_info.HYPERVISOR = sub_node.childNodes[0].nodeValue.encode('utf8')
                        image_list.append(image_info)
            else:
                logger.debug('file : %s is not exisit!' %image_list_file)            
        return image_list

    def euca_reg_domain_user_logon(self, userName, password, domain):
        '''  nyeo
        如果是在线模式：
            1、转发调用LdapThriftServer API euca_reg_domain_user_logon()进行认证
            2、认证成功时，将认证信息保存
            /var/lib/eucalyptus/.luhya/users/username/logon.ini
        如果是离线模式：
           从/var/lib/eucalyptus/.luhya/users/username/logon.in读取信息进行认证。用户名>、密码、domain匹配时，认证成功
        注：
        logon.xml(如：logon.xml)格式如下：
        <userInfo>   
            <userName>sam.wei</userName>
            <logonName>sam.wei</logonName>
            <password>=123456 （MD5）</password>
            <domain>pcbot.biz</domain>
        </userInfo>
        '''
        ret = -5
        # can use super user
        if userName=='super' and password=='super':
            return 0
        if _is_online():
            logger.info('real ldap is online')
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                ret = OpenLdap.p_user_logon(ldap_ip,userName,password,domain)
                logger.info('logon return:%d' %ret)
                if ret==0:        #logon success       
                    userInfo = OpenLdap.get_user_info(ldap_ip,userName)
                    logger.info('user info:%s' %str(userInfo))
                    _save_user_info(userInfo)
                else:
                    logger.debug('user : %s logon error!' %userName)
            else:
                logger.debug('get real ldap ip is error!')
        else:
            logger.info('real clc not online')
            user_info_file = USER_ROOT+userName+'/'+USER_LOGON_FILE
            if os.path.exists(user_info_file):
                logonUser = _get_user_info(user_info_file)
                logger.info('user info:%s' %str(logonUser))
                m = hashlib.md5()
                m.update(password)
                md5Password = m.hexdigest()
                if md5Password==logonUser.bCryptedPassword:
                    ret = 0                 # logon success
                else:
                    ret = -2                # the password is error
            else:
                ret = -5                    # no this user or this user never logon
        return ret


    def luhya_reg_is_admin(self , userName):
        '''  nyeo
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_is_admin(userName)
        如果不在线：
            返回 False
        '''
        ret = False
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                ret = OpenLdap.p_is_admin(ldap_ip,userName)
            else:
                logger.debug('get real ldap ip is error!')	        		
        return ret
	
    def luhya_reg_get_node_migrate_list(self ,):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_node_migrate_list()
        如果不在线：
            返回 []
        '''
        on_line = _is_online()
        nc_migrateList = []
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_get_node_migrate_list() ldapIP error!')               
            else:
               nc_migrateList = OpenLdap.p_get_live_migrate_node_list(ldap_ip)

        return nc_migrateList
    
    def luhya_reg_get_available_snapshot_num(self,userName,imageID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_available_snapshot_num(userName,imageID)
        如果不在线：
            返回 0
        ''' 
        on_line = _is_online()
        snapshot_num = 0
        if on_line:
           ldap_ip = utility.get_real_ldap()
           if ldap_ip == None:
              logging.error('luhya_reg_get_available_snapshot_num() ldapIP error!')
           else:
              snapshot_num = OpenLdap.p_get_available_snapshot_num(ldap_ip,userName,imageID)
        return snapshot_num 
 
    def luhya_reg_get_current_snapshot_id(self,userName,imageID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_current_snapshot_id(userName,imageID)
        如果不在线：
            返回 -1
        '''
        snapshot_id = -1 
        on_line = _is_online()
        if on_line:
           ldap_ip = utility.get_real_ldap()
           if ldap_ip == None:
              logging.error('luhya_reg_get_current_snapshot_id() ldapIP error!')              
           else:
              snapshot_id = OpenLdap.p_get_current_snapshot_id(ldap_ip,userName,imageID)

        return snapshot_id         

    def luhya_reg_set_current_snapshot_id(self,userName,imageID,snapshotID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_set_current_snapshot_id(userName,imageID,snapshotID)
        如果不在线：
            返回 False
        '''
        ret = False        
        on_line = _is_online()
        if on_line:
           ldap_ip = utility.get_real_ldap()
           if ldap_ip == None:
              logging.error('luhya_reg_set_current_snapshot_id() ldapIP error!')
           else:
              ret = OpenLdap.p_set_current_snapshot_id_to_ldap(ldap_ip,userName,imageID,snapshotID)
        return ret        


    def luhya_reg_get_snapshot_list(self,userName,imageID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_snapshot_list(userName,imageID)
        如果不在线：
            返回 []
        '''
        snapshot_list = []
        on_line = _is_online()
        if on_line:
           ldap_ip = utility.get_real_ldap()
           if ldap_ip == None:
              logging.error('luhya_reg_get_snapshot_list() ldapIP error!')
           else:
              snapshot_list = OpenLdap.p_get_snapshot_list(ldap_ip,userName,imageID)
        return snapshot_list
  
    def luhya_reg_get_snapshotInfo_by_id(self,userName,imageID,snapshotID):
        '''  booth
         调用 is_online()判断本机是否在线:
         如果在线：
             调用真正ldap的luhya_reg_get_snapshotInfo_by_id(userName,imageID,snapshotID)
         如果不在线：
             返回 None
         '''
        snapInfo = thd_snapshot()
        on_line = _is_online()
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_get_snapshotInfo_by_id() ldapIP error!')
            else:
               snapInfo = OpenLdap.p_get_snapshotInfo_by_id(ldap_ip,userName,imageID,snapshotID)
        
        return  snapInfo                  
            
    def luhya_reg_add_snapshot(self,snapshotInfo):
        '''
         调用 is_online()判断本机是否在线:
         如果在线：
             调用真正ldap的luhya_reg_add_snapshot(snapshotInfo)
         如果不在线：
             返回 False
        '''
        ret = False
        on_line = _is_online()
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_add_snapshot() ldapIP error!')
               ret = False
            else:
               ret = OpenLdap.p_add_snapshot_to_ldap(ldap_ip,snapshotInfo)
        else:
            ret = False             
        return ret       
         
    def luhya_reg_modify_snapshot(self,snapshotInfo):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_modify_snapshot(snapshotInfo)
        如果不在线：
            返回 False
        '''
        ret = False
        on_line = _is_online()
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_modify_snapshot() ldapIP error!')
               ret = False
            else:
               ret = OpenLdap.p_modify_snapshot(ldap_ip,snapshotInfo)
        else:
            ret = False        
        return ret         
           
    def luhya_reg_delete_snapshot(self,userName,imageID,snapshotID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_delete_snapshot(userName,imageID,snapshotID)
        如果不在线：
            返回 False
        '''
        on_line = _is_online()
        ret = False 
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_delete_snapshot() ldapIP error!')
               ret = False
            else:
               ret = OpenLdap.p_delete_snapshot_to_ldap(ldap_ip,userName, imageID, snapshotID)
        else:
            ret = False        
        return ret        
         
    def luhya_reg_get_available_snapshot_id(self,userName,imageID):
        ''' booth
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_available_snapshot_id(userName,imageID)
        如果不在线：
            返回 -1
        '''
        ret = -1
        on_line = _is_online()
        if on_line:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip == None:
               logging.error('luhya_reg_get_available_snapshot_id() ldapIP error!')
               ret = -1
            else:
               ret = OpenLdap.p_get_available_snapshot_id(ldap_ip,userName,imageID)
        else:
            ret = -1        
        return ret        
 
    def luhya_reg_get_nodeinfo_by_nodeIp(self, nodeIp):
        ''' harrison
        调用 is_online()判断本机是否在线:
        如果在线：
            调用真正ldap的luhya_reg_get_nodeinfo_by_nodeIp (nodeIp)获得nodeInfo
        如果不在线：
            查看/var/lib/eucalyptus/.luhya/ldapCache/是否有local_node.ini文件，如果有：
               从local_node.ini中取得nodeInfo地址返回
           如果没有：
               返回None
        '''
        node_info = None
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            logger.info('luhya_reg_get_nodeinfo_by_nodeIp ldap ip: %s' %ldap_ip)
            if ldap_ip!=None:
                node_info = OpenLdap.p_get_nodeinfo_by_ip(ldap_ip,nodeIp)
        else:
            #get node info from cache file
            if(os.path.exists(NODE_INFO_FILE)):
                node_info = _get_node_info()
        if node_info==None:
            node_info = thd_NodeInfo()
        return node_info        
  
    def luhya_reg_get_clusterinfo_by_cluster(self,clusterName):
        '''   harrison
        调用 is_online()判断本机是否在线
        如果在线：
            调用真正ldap的luhya_reg_get_cluster_ip(clusterName)获得clusterInfo
        如果不在线：
            查看/var/lib/eucalyptus/.luhya/ldapCache/是否有cluster.ini文件，如果有：
                从cluster.ini中取得clusterInfo地址返回
            如果没有：
                返回None        
        '''
        cluster_info = None
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                cluster_info = OpenLdap.get_clusterinfo_by_cluster(ldap_ip,clusterName)
                logger.debug('the cluster info:%s' %str(cluster_info))
            pass
        else:
            if(os.path.exists(CLUSTER_INFO_FILE)):
                #get node info from cache file
                cluster_info = _get_cluster_info()
        if cluster_info==None:
            cluster_info = thd_ClusterInfo()
        return cluster_info        
         
    def luhya_reg_get_max_private_instances(self , user):
        '''   nyeo
        如果是在线模式：
            转发LdapThriftServer luhya_reg_get_max_private_instances API获取个数；
        如果是离线模式：
            直接返回1
        '''
        ret = 1
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                ret = OpenLdap.get_max_private_instances(ldap_ip,user)
            else:
                logger.error('luhya_reg_get_max_private_instances: get real ldap ip is error')
        return ret
 
    def luhya_reg_is_registered(self ,servID,hostIp):
        '''   nyeo
        调用 is_online()判断本机是否在线
        如果在线：
            调用真正的ldap的接口luhya_reg_is_registered(servID,hostIp)
            得到返回值并返回
        如果不在线：
            查看/var/lib/eucalyptus/ldapcaches/下是否有local_node.xml文件
                如果没有:
                    返回FALSE(没有注册)
                如果有：
                    返回TRUE (已经注册)
        '''
        ret = False
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            logger.debug('luhya_reg_is_registered : ldap ip is:%s' %ldap_ip)
            if ldap_ip!=None:
                ret = OpenLdap.p_is_register(ldap_ip,servID,hostIp)
            else:
                logger.error('luhya_reg_is_registered: get real ldap ip is error')
        else:
            if os.path.exists(NODE_INFO_FILE):
                ret=True
        return ret
    
    def luhya_reg_is_online(self,):
        return _is_online()

    def luhya_reg_get_all_domains(self ,):
        domainList = []
        if _is_online():
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None: 
                domainList=OpenLdap.get_all_domains(ldap_ip)
            else:
                logger.error('luhya_reg_get_all_domains: get real ldap ip is error')
        return domainList

class _connect_server_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        logger.info(' _connect_server_thread running ...')
        global g_online
        ldap_ip = None
        clc_ip = None
        testIntv = OFFLINE_CONNECT_INTV
        while True:
            ldap_ip = utility.get_real_ldap()
            clc_ip = _get_clc_ip_from_xml()   
            if ldap_ip!=None:
                if clc_ip == None:
                    clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                    if clc_ip!=None:
                        logger.debug('save the clc ip!')
                        _save_clc_ip(clc_ip)
                    else:
                        logger.debug('get real clc ip error!')
            else:
                logger.debug('get real ldap ip error!')
            
            if ldap_ip==None or clc_ip == None:
                logger.debug('the real ldap ip or clc ip is none!')
            else:
                break
            time.sleep(OFFLINE_CONNECT_INTV)

        while True:
            ''' nyeo
            调用真实的ldap的luhya_reg_is_online()和clc的luhya_res_is_online()
            (调用时将超时设为15秒)
            如果两者都能获得返回值，将全局变量g_online置为True,时间间隔testIntv置为180(用宏)；
            否则全局变量g_online置为False，时间间隔testIntv置为5(用宏)
            '''
            if OpenLdap.p_ldap_online(ldap_ip) and OpenLdap.p_clc_online(clc_ip):
                if not g_online:
                    g_online_switch.acquire()
                    g_online = True
                    g_online_switch.release()
                    testIntv = ONLINE_CONNECT_INTV
            else:
               if g_online:
                   g_online_switch.acquire()
                   g_online=False
                   g_online_switch.release()
                   testIntv = OFFLINE_CONNECT_INTV
                                  
            time.sleep(testIntv)

        
# g_LdapThriftServer_main_interface,LdapThriftServer main interface, starting point 
class g_LdapThriftServer_main_interface(threading.Thread):
    "g_LdapThriftServer_main_interface"

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        local_ip=None
        while True:
            local_ip = utility.get_local_publicip()
            if local_ip!=None:
                logger.warn('local ip:%s' % local_ip)
                break
            else:
                logger.error('get local ip is error !')
                time.sleep(DEFAULT_DELAY)
            
        handler = ldapApiHandler()
        processor = ldapApi.Processor(handler)
        transport = TSocket.TServerSocket(local_ip, thd_port.THRIFT_LDAP_PORT)
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
    conect_server = _connect_server_thread()
    conect_server.start()
       
    LdapThriftServer_main = g_LdapThriftServer_main_interface()
    LdapThriftServer_main.start()
        
    log_string = 'started g_LdapThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string)
    return 0     #sys.exit()


def postInit (user_data):
    pass
