import sys

sys.path.append('./gen-py')
sys.path.append("/usr/lib/python2.6/site-packages")

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from CloudbotWebManagement import ldapApi
from CloudbotWebManagement import clcApi
from CloudbotWebManagement import nodeApi
from CloudbotWebManagement.ttypes import *

import commands

def get_clc_ip():
    clcIP = None
    try:
        transport = TSocket.TSocket('192.168.99.148', thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        clcIP = client.luhya_reg_getClcIp()
        transport.close()
    except Thrift.TException, tx:
        print '%s' % (tx.message)
    return clcIP


def get_all_images():
    imageList = None
    try:
        transport = TSocket.TSocket('192.168.99.155', thd_port.THRIFT_LDAP_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = ldapApi.Client(protocol)
        transport.open()
        imageList = client.luhya_reg_getImageList()
        transport.close()
    except Thrift.TException, tx:
        print '%s' % (tx.message)
    return imageList

def p_set_backup_state( userName, imageID, state):
    clcIp = '192.168.99.180'
    ret = False
    if clcIp!=None:
        try:
            transport = TSocket.TSocket(clcIp, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_set_backup_state(userName,imageID,state)
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret


def p_modify_user( userInfo):
    ldapIp = '192.168.99.180'
    ret = False
    if ldapIp!=None:
        try:
            transport = TSocket.TSocket(ldapIp, thd_port.THRIFT_LDAP_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = ldapApi.Client(protocol)
            transport.open()
            ret = client.luhya_reg_modify_user(userInfo)
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret


def g_get_all_serviceIp( ):
    ldapIp = '192.168.99.148'
    ret = None
    if ldapIp!=None:
        try:
            transport = TSocket.TSocket(ldapIp, thd_port.THRIFT_LDAP_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = ldapApi.Client(protocol)
            transport.open()
            ret = client.luhya_reg_get_all_service_ip()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret

def g_get_service_by_Ip( hostIp):
    ldapIp = '192.168.99.148'
    ret = None
    if ldapIp!=None:
        try:
            transport = TSocket.TSocket(ldapIp, thd_port.THRIFT_LDAP_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = ldapApi.Client(protocol)
            transport.open()
            ret = client.luhya_reg_get_services_by_ip(hostIp)
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret


def stop_service( hostIp):
    ret = None
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_clc_stop_service()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret


def start_service( hostIp):
    ret = None
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_clc_start_service()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
            ret = False
	return ret


def p_stop_service(serviceName):
    ret = True
    cmd_line = None
    if p_is_service_start(serviceName) :
        cmd_line = 	'service '+ serviceName + ' stop'	
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        if cmd_status != 0:
            ret = False        
    return ret


def p_is_service_start(serviceName):
    ret = False
    cmd_line = 'service '+ serviceName + ' status'
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    print cmd_output
    if cmd_status == 0:
        if cmd_output.find('running')>-1:
			ret = True
    return ret

def get_ldap_resource( hostIp):
    ret = None
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_LDAP_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = ldapApi.Client(protocol)
            transport.open()
            ret = client.luhya_reg_get_current_resource()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
    return ret

def get_nc_resource( hostIp):
    ret = None
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_NC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = nodeApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_nc_get_current_resource()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
    return ret
    
def get_clc_resource( hostIp):
    ret = None
    if hostIp!=None:
        try:
            transport = TSocket.TSocket(hostIp, thd_port.THRIFT_CLC_PORT)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = clcApi.Client(protocol)
            transport.open()
            ret = client.luhya_res_clc_get_current_resource()
            transport.close()
        except Thrift.TException, tx:
            print 'is some error %s' %str(tx)
    return ret    
res = get_ldap_resource('192.168.99.148')
print res
res = get_clc_resource('192.168.99.148')
print res
