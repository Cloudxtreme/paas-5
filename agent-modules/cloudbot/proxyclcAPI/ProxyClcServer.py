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
# Author: tony li tony.li@sinobot.com.cn
import sys
import logging
sys.path.append("/usr/lib/python2.6/site-packages")
from cloudbot.proxyinterface import clcApi
from cloudbot.proxyinterface.ttypes import * 
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

from cloudbot.utils import OpenLdap,utility
from cloudbot.utils.const_def import *
import os
import threading
import xml.dom.minidom
import codecs
import socket,struct,fcntl

logger = utility.init_log()


def _is_online():
    ret = False
    ldap_ip = utility.get_ldap_server()
    if ldap_ip!=None:
        ret = OpenLdap.p_ldap_online(ldap_ip)
    return ret   


def _save_client_infos_to_file(client_infos,client_info_file):
    ret = False
    if len(client_infos)!=0:        
        impl = xml.dom.minidom.getDOMImplementation()
        dom=impl.createDocument(None,'clientInfos',None)        
        root = dom.documentElement
        for client_info in client_infos:
            itemTop = utility.make_easy_tag(dom,'clientInfo','')
            text=client_info.client_data_id
            item = utility.make_easy_tag(dom,'client_data_id',text)
            itemTop.appendChild(item)
            text=client_info.image_id
            item = utility.make_easy_tag(dom,'image_id',text)
            itemTop.appendChild(item)
            text=unicode(client_info.image_name,'utf8')
            item = utility.make_easy_tag(dom,'image_name',text)
            itemTop.appendChild(item)
            text = unicode(client_info.user,'utf8')
            item = utility.make_easy_tag(dom,'user',text)
            itemTop.appendChild(item)
            text = str(client_info.image_category)
            item = utility.make_easy_tag(dom,'image_category',text)
            itemTop.appendChild(item)
            text = str(client_info.image_size)
            item = utility.make_easy_tag(dom,'image_size',text)
            itemTop.appendChild(item)
            text = client_info.vmconfig_id
            item = utility.make_easy_tag(dom,'vmconfig_id',text)
            itemTop.appendChild(item)
            if client_info.node_ip!=None:  
                text = client_info.node_ip
                item = utility.make_easy_tag(dom,'node_ip',text)
                itemTop.appendChild(item)
            if client_info.user_department_id!=None:
                text = str(client_info.user_department_id)
                item = utility.make_easy_tag(dom,'user_department_id',text)
                itemTop.appendChild(item)
            if client_info.os_type!=None and len(client_info.os_type)>0:
                text = client_info.os_type
                item = utility.make_easy_tag(dom,'os_type',text)
                itemTop.appendChild(item)
            if client_info.platform!=None and len(client_info.platform)>0:
                text = client_info.platform
                item = utility.make_easy_tag(dom,'platform',text)
                itemTop.appendChild(item)
              
            if client_info.is_assign_node:
                text = 'TRUE'
            else:
                text='FALSE'
            item = utility.make_easy_tag(dom,'is_assign_node',text)
            itemTop.appendChild(item)  
            # save vm_info
            if client_info.vm_info!=None:
                item1 = utility.make_easy_tag(dom,'vm_info','')
                if client_info.vm_info.vm_cpu!=None:          
                    text = str(client_info.vm_info.vm_cpu)
                    item = utility.make_easy_tag(dom,'vm_cpu',text)
                    item1.appendChild(item)
                if client_info.vm_info.vm_memory!=None:
                    text = str(client_info.vm_info.vm_memory)
                    item = utility.make_easy_tag(dom,'vm_memory',text)
                    item1.appendChild(item)
                if client_info.vm_info.vm_disk!=None:
                    text = str(client_info.vm_info.vm_disk)
                    item = utility.make_easy_tag(dom,'vm_disk',text)
                    item1.appendChild(item)
                if client_info.vm_info.machine_name!=None:
                    text = unicode(client_info.vm_info.machine_name,'utf8')
                    item = utility.make_easy_tag(dom,'machine_name',text)
                    item1.appendChild(item)
                if client_info.vm_info.vm_protocol!=None and len(client_info.vm_info.vm_protocol)>0:
                    text = client_info.vm_info.vm_protocol
                    item = utility.make_easy_tag(dom,'vm_protocol',text)
                    item1.appendChild(item)
                if client_info.vm_info.display_mode!=None and len(client_info.vm_info.display_mode)>0:
                    text = client_info.vm_info.display_mode
                    item = utility.make_easy_tag(dom,'display_mode',text)
                    item1.appendChild(item)
                if client_info.vm_info.is_clear_power_off!=None:
                    if client_info.vm_info.is_clear_power_off:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_clear_power_off',text)
                    item1.appendChild(item)
                if client_info.vm_info.vm_port!=None:
                    text = str(client_info.vm_info.vm_port)
                    item = utility.make_easy_tag(dom,'vm_port',text)
                    item1.appendChild(item)
                if client_info.vm_info.vm_password!=None:
                    text = client_info.vm_info.vm_password
                    item = utility.make_easy_tag(dom,'vm_password',text)
                    item1.appendChild(item)
                if client_info.vm_info.is_run_without_copy!=None:
                    if client_info.vm_info.is_run_without_copy:
                        text = 'TRUE'
                    else:
                        text='FALSE'
                    item = utility.make_easy_tag(dom,'is_run_without_copy',text)
                    item1.appendChild(item)
                if client_info.vm_info.is_permit_write_file_to_image!=None:
                    if client_info.vm_info.is_permit_write_file_to_image:
                        text = 'TRUE'
                    else:
                        text='FALSE'
                    item = utility.make_easy_tag(dom,'is_permit_write_file_to_image',text)
                    item1.appendChild(item)
                if client_info.vm_info.number_of_screens!=None:
                    text = str(client_info.vm_info.number_of_screens)
                    item = utility.make_easy_tag(dom,'number_of_screens',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)
            # save net_info
            if client_info.net_info!=None:
                item1 = utility.make_easy_tag(dom,'net_info','')           
                if client_info.net_info.domain!=None and len(client_info.net_info.domain)>0:
                    text = client_info.net_info.domain
                    item = utility.make_easy_tag(dom,'domain',text)
                    item1.appendChild(item)
                if client_info.net_info.net_mode!=None and len(client_info.net_info.net_mode)>0:
                    text = client_info.net_info.net_mode
                    item = utility.make_easy_tag(dom,'net_mode',text)
                    item1.appendChild(item)
                if client_info.net_info.ip_dhcp!=None:
                    if client_info.net_info.ip_dhcp:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'ip_dhcp',text)
                    item1.appendChild(item)
                if client_info.net_info.dns_dhcp!=None:
                    if client_info.net_info.dns_dhcp:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'dns_dhcp',text)
                    item1.appendChild(item)
                if client_info.net_info.public_ip!=None and len(client_info.net_info.public_ip)>0:
                    text = client_info.net_info.public_ip
                    item = utility.make_easy_tag(dom,'public_ip',text)
                    item1.appendChild(item)
                if client_info.net_info.private_ip!=None and len(client_info.net_info.private_ip)>0:
                    text = client_info.net_info.private_ip
                    item = utility.make_easy_tag(dom,'private_ip',text)
                    item1.appendChild(item)
                if client_info.net_info.public_mac!=None and len(client_info.net_info.public_mac)>0:
                    text = client_info.net_info.public_mac
                    item = utility.make_easy_tag(dom,'public_mac',text)
                    item1.appendChild(item)
                if client_info.net_info.private_mac!=None and len(client_info.net_info.private_mac)>0:
                    text = client_info.net_info.private_mac
                    item = utility.make_easy_tag(dom,'private_mac',text)
                    item1.appendChild(item)
                if client_info.net_info.gateway!=None and len(client_info.net_info.gateway)>0:
                    text = client_info.net_info.gateway
                    item = utility.make_easy_tag(dom,'gateway',text)
                    item1.appendChild(item)
                if client_info.net_info.netmask!=None and len(client_info.net_info.netmask)>0:
                    text = client_info.net_info.netmask
                    item = utility.make_easy_tag(dom,'netmask',text)
                    item1.appendChild(item)
                if client_info.net_info.dns!=None and len(client_info.net_info.dns)>0:
                    text = client_info.net_info.dns
                    item = utility.make_easy_tag(dom,'dns',text)
                    item1.appendChild(item)
                if client_info.net_info.wins!=None and len(client_info.net_info.wins)>0:
                    text = client_info.net_info.wins
                    item = utility.make_easy_tag(dom,'wins',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)  
            #save run_schedule
            if client_info.run_schedule!=None:
                item1 = utility.make_easy_tag(dom,'run_schedule','')           
                if client_info.run_schedule.run_model!=None:
                    text = client_info.run_schedule.run_model
                    item = utility.make_easy_tag(dom,'run_model',text)
                    item1.appendChild(item)
                if client_info.run_schedule.power_on_time!=None:
                    text = client_info.run_schedule.power_on_time
                    item = utility.make_easy_tag(dom,'power_on_time',text)
                    item1.appendChild(item)
                if client_info.run_schedule.power_off_time!=None:
                    text = client_info.run_schedule.power_off_time
                    item = utility.make_easy_tag(dom,'power_off_time',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)
            #save peripheral
            if client_info.peripheral!=None:
                item1 = utility.make_easy_tag(dom,'peripheral','')           
                if client_info.peripheral.is_support_peripheral!=None:
                    if client_info.peripheral.is_support_peripheral:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_support_peripheral',text)
                    item1.appendChild(item)
                if client_info.peripheral.is_support_usb!=None:
                    if client_info.peripheral.is_support_usb:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_support_usb',text)
                    item1.appendChild(item)
                if client_info.peripheral.max_usb_number!=None:
                    text = str(client_info.peripheral.max_usb_number)
                    item = utility.make_easy_tag(dom,'max_usb_number',text)
                    item1.appendChild(item)
                if client_info.peripheral.is_support_parallel!=None:
                    if client_info.peripheral.is_support_parallel:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_support_parallel',text)
                    item1.appendChild(item)
                if client_info.peripheral.is_support_com!=None:
                    if client_info.peripheral.is_support_com:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_support_com',text)
                    item1.appendChild(item)
                if client_info.peripheral.is_cdrom!=None:
                    if client_info.peripheral.is_cdrom:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_cdrom',text)
                    item1.appendChild(item)
                if client_info.peripheral.is_external_device!=None:
                    if client_info.peripheral.is_external_device:
                        text = 'TRUE'
                    else:
                        text = 'FALSE'
                    item = utility.make_easy_tag(dom,'is_external_device',text)
                    item1.appendChild(item)
                if client_info.peripheral.external_disk!=None:
                    text = str(client_info.peripheral.external_disk)
                    item = utility.make_easy_tag(dom,'external_disk',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)
            #save snapshot
            if client_info.snapshot!=None:
                item1 = utility.make_easy_tag(dom,'snapshot','')           
                if client_info.snapshot.is_snapshot!=None:
                    if client_info.snapshot.is_snapshot:
                        text='TRUE'
                    else:
                        text='FALSE'
                    item = utility.make_easy_tag(dom,'is_snapshot',text)
                    item1.appendChild(item)
                if client_info.snapshot.max_snapshot!=None:
                    text = str(client_info.snapshot.max_snapshot)
                    item = utility.make_easy_tag(dom,'max_snapshot',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)
            #save thermophoresis
            if client_info.thermophoresis!=None:
                item1 = utility.make_easy_tag(dom,'thermophoresis','')           
                if client_info.thermophoresis.is_thermophoresis!=None:
                    if client_info.thermophoresis.is_thermophoresis:
                        text='TRUE'
                    else:
                        text='FALSE'
                    item = utility.make_easy_tag(dom,'is_thermophoresis',text)
                    item1.appendChild(item)
                if client_info.thermophoresis.thermophoresis_cluster!=None:
                    text = client_info.thermophoresis.thermophoresis_cluster
                    item = utility.make_easy_tag(dom,'thermophoresis_cluster',text)
                    item1.appendChild(item)
                if client_info.thermophoresis.thermophoresis_node!=None:
                    text = client_info.thermophoresis.thermophoresis_node
                    item = utility.make_easy_tag(dom,'thermophoresis_node',text)
                    item1.appendChild(item)
                itemTop.appendChild(item1)
            #save instance_state
            if client_info.instance_state!=None:
                item1 = utility.make_easy_tag(dom,'instance_state','')           
                if client_info.instance_state.is_can_run:
                    text='TRUE'
                else:
                    text='FALSE'
                item = utility.make_easy_tag(dom,'is_can_run',text)
                item1.appendChild(item)
                if client_info.instance_state.instance_type!=None:
                    text = client_info.instance_state.instance_type
                    item = utility.make_easy_tag(dom,'instance_type',text)
                    item1.appendChild(item)
                if client_info.instance_state.download_progress!=None:
                    text = str(client_info.instance_state.download_progress)
                    item = utility.make_easy_tag(dom,'download_progress',text)
                    item1.appendChild(item)
                if client_info.instance_state.state!=None:
                    text = str(client_info.instance_state.state)
                    item = utility.make_easy_tag(dom,'state',text)
                    item1.appendChild(item)
                if client_info.instance_state.is_local:
                    text='TRUE'
                else:
                    text='FALSE'
                item = utility.make_easy_tag(dom,'is_local',text)
                item1.appendChild(item)
                itemTop.appendChild(item1)            
            root.appendChild(itemTop)

        domcopy = dom.cloneNode(True)
        utility.indent_xml(domcopy, domcopy.documentElement)
        f=file(client_info_file,'w')
        writer = codecs.lookup('utf-8')[3](f)
        domcopy.writexml(writer, encoding = 'utf-8')
        domcopy.unlink()
        writer.close()

        ret = True
    return ret 

def _get_client_info_from_file(file_name):
    client_infos=[]
    dom = xml.dom.minidom.parse(file_name)
    root = dom.documentElement
    el = dom.childNodes
    for xml_node in el:
        xml_node_list = xml_node.childNodes
        for client in xml_node_list:
            client_info = thd_client_info()
            clients = client.childNodes
            for xml_client in clients: 
                if xml_client.nodeName=='image_id':
                    client_info.image_id = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='image_name':
                    client_info.image_name = xml_client.childNodes[0].nodeValue.encode('utf8')
                elif xml_client.nodeName=='client_data_id':
                    client_info.client_data_id = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='node_ip':
                    client_info.node_ip = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='user':
                    client_info.user = xml_client.childNodes[0].nodeValue.encode('utf8')
                elif xml_client.nodeName=='user_department_id':
                    client_info.user_department_id = int(xml_client.childNodes[0].nodeValue)
                elif xml_client.nodeName=='os_type':
                    client_info.os_type = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='platform':
                    client_info.platform = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='image_category':
                    client_info.image_category = int(xml_client.childNodes[0].nodeValue)
                elif xml_client.nodeName=='image_size':
                    client_info.image_size = int(xml_client.childNodes[0].nodeValue)
                elif xml_client.nodeName=='vmconfig_id':
                    client_info.vmconfig_id = xml_client.childNodes[0].nodeValue
                elif xml_client.nodeName=='is_assign_node':
                    if xml_client.childNodes[0].nodeValue=='TRUE':
                        client_info.is_assign_node = True
                    else:
                        client_info.is_assign_node = False
                elif xml_client.nodeName=='vm_info':
                    vm_info = thd_vm_info()
                    vm_info_clients = xml_client.childNodes
                    for xml_vm_info in vm_info_clients:
                        if xml_vm_info.nodeName=='vm_cpu':
                            vm_info.vm_cpu = int(xml_vm_info.childNodes[0].nodeValue)
                        elif xml_vm_info.nodeName=='vm_memory':
                            vm_info.vm_memory = int(xml_vm_info.childNodes[0].nodeValue)
                        elif xml_vm_info.nodeName=='vm_disk':
                            vm_info.vm_disk = int(xml_vm_info.childNodes[0].nodeValue)
                        elif xml_vm_info.nodeName=='machine_name':
                            vm_info.machine_name = xml_vm_info.childNodes[0].nodeValue.encode('utf8')
                        elif xml_vm_info.nodeName=='vm_protocol':
                            vm_info.vm_protocol = xml_vm_info.childNodes[0].nodeValue
                        elif xml_vm_info.nodeName=='display_mode':
                            vm_info.display_mode = xml_vm_info.childNodes[0].nodeValue
                        elif xml_vm_info.nodeName=='is_clear_power_off':
                            if xml_vm_info.childNodes[0].nodeValue=='TRUE':
                                vm_info.is_clear_power_off = True
                            else:
                                vm_info.is_clear_power_off = False
                        elif xml_vm_info.nodeName=='vm_port':
                            vm_info.vm_port = int(xml_vm_info.childNodes[0].nodeValue)
                        elif xml_vm_info.nodeName=='vm_password':
                            vm_info.vm_password = xml_vm_info.childNodes[0].nodeValue
                        elif xml_vm_info.nodeName=='is_run_without_copy':
                            if xml_vm_info.childNodes[0].nodeValue=='TRUE':
                                vm_info.is_run_without_copy = True
                            else:
                                vm_info.is_run_without_copy = False
                        elif xml_vm_info.nodeName=='is_permit_write_file_to_image':
                            if xml_vm_info.childNodes[0].nodeValue=='TRUE':
                                vm_info.is_permit_write_file_to_image = True
                            else:
                                vm_info.is_permit_write_file_to_image = False
                        elif xml_vm_info.nodeName=='number_of_screens':
                            vm_info.number_of_screens = int(xml_vm_info.childNodes[0].nodeValue)                         
                    client_info.vm_info = vm_info
                elif xml_client.nodeName=='net_info':
                    net_info = thd_net_info()
                    net_info_clients = xml_client.childNodes
                    for xml_net_info in net_info_clients:
                        if xml_net_info.nodeName=='domain':
                            net_info.domain = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='net_mode':
                            net_info.net_mode = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='ip_dhcp':
                            if xml_net_info.childNodes[0].nodeValue=='TRUE':
                                net_info.ip_dhcp = True
                            else:
                                net_info.ip_dhcp = False
                        elif xml_net_info.nodeName=='dns_dhcp':
                            if xml_net_info.childNodes[0].nodeValue=='TRUE':
                                net_info.dns_dhcp = True
                            else:
                                net_info.dns_dhcp = False
                        elif xml_net_info.nodeName=='public_ip':
                            net_info.public_ip = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='private_ip':
                            net_info.private_ip = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='public_mac':
                            net_info.public_mac = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='private_mac':
                            net_info.private_mac = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='netmask':
                            net_info.netmask = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='gateway':
                            net_info.gateway = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='dns':
                            net_info.dns = xml_net_info.childNodes[0].nodeValue
                        elif xml_net_info.nodeName=='wins':
                            net_info.wins = xml_net_info.childNodes[0].nodeValue
                    client_info.net_info = net_info
                elif xml_client.nodeName=='peripheral':
                    peripheral = thd_peripheral()
                    peripheral_clients = xml_client.childNodes
                    for xml_peripheral in peripheral_clients:
                        if xml_peripheral.nodeName=='is_support_peripheral':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_support_peripheral = True
                            else:
                                peripheral.is_support_peripheral = False
                        elif xml_peripheral.nodeName=='is_support_usb':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_support_usb = True
                            else:
                                peripheral.is_support_usb = False
                        elif xml_peripheral.nodeName=='is_support_com':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_support_com = True
                            else:
                                peripheral.is_support_com = False
                        elif xml_peripheral.nodeName=='is_support_parallel':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_support_parallel = True
                            else:
                                peripheral.is_support_parallel = False
                        elif xml_peripheral.nodeName=='is_cdrom':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_cdrom = True
                            else:
                                peripheral.is_cdrom = False
                        elif xml_peripheral.nodeName=='is_external_device':
                            if xml_peripheral.childNodes[0].nodeValue=='TRUE':
                                peripheral.is_external_device = True
                            else:
                                peripheral.is_external_device = False
                        elif xml_peripheral.nodeName=='max_usb_number':
                            peripheral.max_usb_number = int(xml_peripheral.childNodes[0].nodeValue)
                        elif xml_peripheral.nodeName=='external_disk':
                            peripheral.external_disk = int(xml_peripheral.childNodes[0].nodeValue)
                    client_info.peripheral= peripheral                  
                elif xml_client.nodeName=='instance_state':
                    instance_state = thd_instance_state()
                    state_clients = xml_client.childNodes
                    for xmlstate in state_clients:
                        if xmlstate.nodeName=='instance_type':
                            instance_state.instance_type = xmlstate.childNodes[0].nodeValue
                        elif xmlstate.nodeName=='is_can_run':
                            if xmlstate.childNodes[0].nodeValue=='TRUE':
                                instance_state.is_can_run = True
                            else:
                                instance_state.is_can_run = False
                        elif xmlstate.nodeName=='download_progress':
                            instance_state.download_progress = int(xmlstate.childNodes[0].nodeValue)
                        elif xmlstate.nodeName=='is_local':
                            if xmlstate.childNodes[0].nodeValue=='TRUE':
                                instance_state.is_local = True
                            else:
                                instance_state.is_local = False
                        elif xmlstate.nodeName=='state':
                            instance_state.state = int(xmlstate.childNodes[0].nodeValue)
                    client_info.instance_state= instance_state
                elif xml_client.nodeName=='snapshot':
                    snapshot = thd_support_snapshot()
                    snapshot_clients = xml_client.childNodes
                    for xml_snapshot in snapshot_clients:
                        if xml_snapshot.nodeName=='max_snapshot':
                            snapshot.max_snapshot = int(xml_snapshot.childNodes[0].nodeValue)
                        elif xml_snapshot.nodeName=='is_snapshot':
                            if xml_snapshot.childNodes[0].nodeValue=='TRUE':
                                snapshot.is_snapshot = True
                            else:
                                snapshot.is_snapshot = False
                    client_info.snapshot= snapshot
                elif xml_client.nodeName=='thermophoresis':
                    thermophoresis = thd_thermophoresis()
                    thermclients = xml_client.childNodes
                    for xmltherm in thermclients:
                        if xmltherm.nodeName=='thermophoresis_cluster':
                            thermophoresis.thermophoresis_cluster = xmltherm.childNodes[0].nodeValue
                        elif xmltherm.nodeName=='thermophoresis_node':
                            thermophoresis.thermophoresis_node = xmltherm.childNodes[0].nodeValue
                        elif xmltherm.nodeName=='is_thermophoresis':
                            if xmltherm.childNodes[0].nodeValue=='TRUE':
                                thermophoresis.is_thermophoresis = True
                            else:
                                thermophoresis.is_thermophoresis = False 
                    client_info.thermophoresis= thermophoresis
                elif xml_client.nodeName=='run_schedule':
                    run_schedule = thd_run_schedule()
                    runclients = xmlclient.childNodes
                    for xmlrun in runclients:
                        if xmlrun.nodeName=='run_model':
                            run_schedule.run_model = xmlrun.childNodes[0].nodeValue
                        elif xmlrun.nodeName=='power_on_time':
                            run_schedule.power_on_time = xmlrun.childNodes[0].nodeValue
                        elif xmlrun.nodeName=='power_off_time':
                            run_schedule.power_off_time = xmlrun.childNodes[0].nodeValue
                    client_info.run_schedule= run_schedule
            if client_info.client_data_id!=None:
                client_infos.append(client_info)        
    return client_infos                  
      
def _read_client_infos(user):
    client_infos = []
    client_info_file = USER_ROOT+user+'/'+CLIENT_INFO_FILE
    if os.path.exists(client_info_file):
        client_infos = _get_client_info_from_file(client_info_file)
    else:
        logger.debug('file : %s is not exisit!' %client_info_file) 
    return client_infos

# save the clientinfos to clientdata.ini file
def _save_client_infos(user,client_infos):
    logger.info('_save_client_infos : %s' %str(client_infos))
    if len(client_infos)==0:
        return True
    client_info_path = USER_ROOT+user+'/'
    if not os.path.exists(client_info_path):
        try:
            os.makedirs(client_info_path)
        except:
            logger.error('Create ' + client_info_path + ' error!')
            return False        
    client_info_file = client_info_path+CLIENT_INFO_FILE
    if(os.path.exists(client_info_file)):                #delete the clientinfo file saved prov
        os.remove(client_info_file)    
    return _save_client_infos_to_file(client_infos,client_info_file)    

def _image_cache_exist(image_id,length):   # the image is cached
    ret = False
    image_cache_file = IMAGE_CACHE_ROOT+image_id+'/machine'
    if os.path.exists(image_cache_file):
        stat = os.stat(image_cache_file)
        if stat.st_size==length:
            ret = True
        else:
            logger.debug('file:%s st_size is not correct!' %image_cache_file)
    return ret

def _get_logon_users():
    users = []
    filelist = os.listdir(USER_ROOT)
    logger.info('_get_logon_users :%s' %filelist) 
    for ln in filelist:
        if os.path.isdir(USER_ROOT+ln):
            users.append(ln)
    return users

def p_get_client_data(user,requestIp):
    client_infos = []
    if _is_online():
        logger.info('real clc is online')
        local_ip = utility.get_local_publicip()
        if local_ip!=None:
            real_ldap_ip = utility.get_real_ldap()
            logger.info('real ldap ip:%s' %real_ldap_ip)
            if real_ldap_ip!=None:
                clc_ip = OpenLdap.get_clc_ip(real_ldap_ip)
                client_infos = OpenLdap.get_client_data(clc_ip,user,local_ip)
                realUser = user
                if user!='super':
                    _save_client_infos(user,client_infos)
                else:
                    realUser = 'admin'
                # update local instance state
                instances = OpenLdap.get_instance_states(local_ip,realUser)

                for client_info in client_infos:
                    if user == 'super' and client_info.node_ip ==local_ip:
                        client_info.run_as_super = True
                    else:
                        client_info.run_as_super = False
                    find_client_info = False
                    for instance in instances:
                        if client_info.node_ip ==local_ip and instance.user ==client_info.user and instance.image_id==client_info.image_id:
                            find_client_info = True
                            client_info.instance_state.state = instance.state
                            client_info.vm_info.vm_port = instance.n_port
                            client_info.vm_info.vm_password = instance.str_password
                            break
                    if not find_client_info and client_info.node_ip ==local_ip:
                        client_info.instance_state.state = thd_TRANSACT_STATE.TERMINATED
            else:
                logger.error('p_get_client_data: real ldap ip error')
        else:
            logger.error('p_get_client_data: get local ip error')
    else:
        logger.info('real clc not online')
        local_ip = utility.get_local_publicip()
        if user=='super':
            logon_users = _get_logon_users()
            logger.info('logon user: %s' %str(logon_users))
            for usrName in logon_users:
                local_client = _read_client_infos(usrName)
                for lcClient in local_client:
                    if lcClient.vm_info.is_clear_power_off:
                        client_infos.append(lcClient)
        else:
            client_infos = _read_client_infos(user)
        logger.info('the saved client info number : %d ' %len(client_infos))
        realUser = user
        if user=='super':
            realUser = 'admin'
        instances = OpenLdap.get_instance_states(local_ip,realUser)
        logger.info('the instance: %s' %str(instances))
        for client_info in client_infos:
            if user == 'super':
                client_info.run_as_super = True
            else:
                client_info.run_as_super = False
            if not client_info.instance_state.is_local:             # remote instance can not be run 
                client_info.instance_state.is_can_run = False
                client_info.instance_state.state = thd_TRANSACT_STATE.TERMINATED
            else:
                if _image_cache_exist(client_info.image_id,client_info.image_size): #the image is cached
                    client_info.instance_state.is_can_run = True
                else:
                    client_info.instance_state.is_can_run = False
            find_client_info = False
            for instance in instances:
                if client_info.instance_state.is_local and instance.user ==client_info.user and instance.image_id==client_info.image_id:
                    find_client_info = True
                    client_info.instance_state.state = instance.state
                    client_info.vm_info.vm_port = instance.n_port
                    client_info.vm_info.vm_password = instance.str_password
                    break
            if not find_client_info:
                client_info.instance_state.state = thd_TRANSACT_STATE.TERMINATED
    logger.debug('p_get_client_data: %s' %str(client_infos))
    return client_infos

class clcApiHandler:

    def luhya_clc_get_client_data(self , user,requestIp):
        '''  nyeo
        调用 is_online()判断本机是否在线
        如果在线：
            1、获得本机的IP地址；
            2、调用真正的clc上的luhya_clc_get_client_data(user,requestIp) 获得clientInfo列表，并将列表保存    到/var/lib/eucalyptus/.luhya/users/username/clientdata.xml 文件中。存放模式如下：
             <clientInfos>   
                <i-02EDA32>
                    <image_id>emi-123456</image_id>
                    <vmconfig_id>asdasd-asdfasdf12345-a11sssdsa</vmconfig_id>
                    <user>sam.wei</user>
                    <machine_name>sam-xp</machine_name>
                    ...
                    <vm_info>
                        <vm_cpu>1</vm_cpu>
                        <vm_momory>2048</vm_memory>
                        ...
                    </vm_info>
                    <net_info>
                        <public_ip>192.168.99.155</public_ip>
                        <provate_ip>0.0.0.0<provate_ip/>
                        ...
                    </net_info>
                </i-02EDA32>
                ...

            </clientInfo>
            3、返回clientInfo列表
        如果不在线：
            判断文件clientdata.ini是否存在，如果存在：
                1、从文件clientdata.ini中读取clientInfo列表；
                2、将clientInfo列表中远程的instance的is_can_run设为false
                3、判断/var/lib/eucalyptus/.luhya/cache/imageID/下machine文件是否存在，若存在，isCanRun为true,反之为false;
                4、调用nc端的luhya_res_get_instances_state(user)获得instance状态列表，根据状态列表更新clientInfo列表；
                5、返回clientInfo列表；
            如果不存在：
                返回None
        '''
        return p_get_client_data(user,requestIp)
        
    def luhya_clc_start_vm(self, clientInfo):	
        ''' harrison
        远程模式(clientData.is_local==False):
            直接调用ClcThriftServer API luhya_clc_start_vm（clientData）启动虚拟机
        本地模式(clientData.is_local==True)：
            调用本地NcThriftServer API luhya_res_start_vm (clientData)启动虚拟机
        '''
        ret = -1
        if (clientInfo.instance_state.is_local):
            local_nc_ip = utility.get_local_publicip()
            if local_nc_ip != None:
                ret =  OpenLdap.p_nc_start_vm(local_nc_ip, clientInfo)
            else:
                logger.debug('get local ip is error!')
        else:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                if clc_ip!=None:
                    ret =  OpenLdap.clc_start_vm(clc_ip, clientInfo)
                else:
                    logger.debug('get real clc ip is error!')
            else:
                logger.debug('get real ldap ip is error!')
        return ret
        	
    def luhya_clc_stop_vm(self, clientInfo): 
        ''' harrison
           如果是在线并且是远程模式：
                转发调用ClcThriftServer API luhya_clc_stop_vm(client_info)停止虚拟机
           如果是在线本地模式或离线模式：
                直接调用NcThriftServer API luhya_nc_stop_vm(client_info)停止虚拟机
        '''        
        ret = False
        if (clientInfo.instance_state.is_local):
            local_nc_ip = utility.get_local_publicip()
            if local_nc_ip != None:
                ret =  OpenLdap.p_nc_stop_vm(local_nc_ip, clientInfo)
        else:
            ldap_ip = utility.get_real_ldap()
            if ldap_ip!=None:
                clc_ip = OpenLdap.get_clc_ip(ldap_ip)
                if clc_ip!=None:
                    ret =  OpenLdap.clc_stop_vm(clc_ip, clientInfo)
                else:
                    logger.debug('get real clc ip is error!')
            else:
                logger.debug('get real ldap ip is error!')
        return ret

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

class _get_proxy_ldap_ip_thread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)    
    def run(self):
        while True:
            local_ip=None           
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                local_ip = socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', 'br0'[:15]))[20:24])
                if local_ip != None:
                    logger.info('local_ip:%s ' %local_ip)
                    fh = open(LDAP_CONF_FILE, 'w')
                    fileStr = 'LDAP_SERVER=\"' + local_ip+'\"'
                    fh.write(fileStr)
                    fh.close()
                    break
            except:
                logger.error('get local ip error !')
            time.sleep(DEFAULT_DELAY)


# ClcThriftServerexternal interface
def preInit (user_data):
    logger.info('pre_init starting ...')
    proxy_ldap_ip_thread = _get_proxy_ldap_ip_thread()
    proxy_ldap_ip_thread.start()
    # start the clc server
    ClcThriftServer_main = g_ClcThriftServer_main_interface()
    ClcThriftServer_main.start()
    
    log_string = 'started g_ClcThriftServer_main_interface pthread,pre_init return'
    logger.info(log_string)
    return 0     #sys.exit()
def postInit (user_data):
  pass
