#!/usr/bin/env python
import sys
import socket
sys.path.append("/usr/lib/python2.6/site-packages")

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from cloudbot.interface import ldapApi
from cloudbot.interface import nodeApi
from cloudbot.interface import walrusApi
from cloudbot.interface import clcApi
from cloudbot.interface.ttypes import *

from cloudbot.utils import OpenLdap




def set_log_level(clc_ip,strLevel):
    ret = -1
    try:
        transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = clcApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_set_log_level(strLevel)
        transport.close()
    except Thrift.TException, tx:
        print 'set_log_level error:%s' % (tx.message)    
    return ret



def get_clc_data(clc_ip,strData):
    ret = None
    try:
        transport = TSocket.TSocket(clc_ip, thd_port.THRIFT_CLC_PORT)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = clcApi.Client(protocol)
        transport.open()
        ret = client.luhya_res_dump_clc_data(strData)
        transport.close()
    except Thrift.TException, tx:
        print 'get_clc_data error:%s' % (tx.message)    
    return ret


