import sys
sys.path.append('../gen-py')

import getopt, sys, os, stat
import socket
import fcntl
import struct

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from CloudbotWebManagement import ldapApi
from CloudbotWebManagement.ttypes import *

LDAP_CONF_FILE = '/etc/eucalyptus/eucalyptus-ldap.conf'

def get_ldap_server():
	"get_ldap_server"
	fh = os.popen ('cat '+LDAP_CONF_FILE)
	setconfig = 1
	for ln in fh.readlines ():
		if 'LDAP_SERVER' in ln:
			ln = ln.strip (' \n')
			ls = ln.rsplit('"')
			ldap_server = ls[1]
			setconfig = 0
			break;
	if(setconfig):
		return None
	return ldap_server


def get_local_publicip():
	"get_local_publicip"
	ldapip = get_ldap_server()
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect((ldapip,80))
	hostip = s.getsockname()[0]
	return hostip
  
def getCurrentIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    localIP = socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', 'eth0'[:15]))[20:24])
    return localIP


def get_clc_ip():
	clcIP = None
	try:
		transport = TSocket.TSocket(get_ldap_server(), thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		clcIP = client.luhya_reg_getClcIp()
		transport.close()
	except Thrift.TException, tx:
		print '%s' % (tx.message)
	return clcIP

def get_certificate_Code(userId):
	certificateCode = None
	try:
		transport = TSocket.TSocket(get_ldap_server(), thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		certificateCode = client.luhya_reg_getCertificateCode(userId)
		transport.close()
	except Thrift.TException, tx:
		print '%s' % (tx.message)
	return certificateCode
 
def get_walrus_info():
	hostip = None
	port = None
	try:
		transport = TSocket.TSocket(get_ldap_server(), thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		hostip = client.luhya_reg_getWalrusIp()
		port = client.luhya_reg_getWalrusPort()
		transport.close()
	except Thrift.TException, tx:
		print '%s' % (tx.message)
	return hostip,port

def get_image_location(imageID):
	location = None
	try:
		transport = TSocket.TSocket(get_ldap_server(), thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		imageInfo = client.luhya_reg_getImageInfo(imageID)
		if(imageInfo!=None):
			location = imageInfo.imageLocation
		transport.close()
	except Thrift.TException, tx:
		print '%s' % (tx.message)
	return location

def update_image_toldap(imageInfo):
	if(imageInfo==None or imageInfo.imageId==None):
		return False
	res = False
	try:
		transport = TSocket.TSocket(get_ldap_server(), thd_port.THRIFT_LDAP_PORT)
		transport = TTransport.TBufferedTransport(transport)
		protocol = TBinaryProtocol.TBinaryProtocol(transport)
		client = ldapApi.Client(protocol)
		transport.open()
		res = client.luhya_reg_updateImageInfo(imageInfo)
		transport.close()
	except Thrift.TException, tx:
		print '%s' % (tx.message)
	return res
	
	
