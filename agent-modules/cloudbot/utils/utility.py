#!/usr/bin/python
#Filename:utility.py

"""
    GET THE RESOUREC FROM CPU,MEMORY AND DISK
    TIME:2012-7-11
    E-MAIL: BOOTH.LI@SINOBOT.COM.CN
"""

import os
import logging
import logging.handlers
import time
import commands
import socket
import fcntl
import struct
from cloudbot.utils import OpenLdap
from cloudbot.interface.ttypes import *
from cloudbot.utils.const_def import *
import xml.dom.minidom
import codecs

def get_current_cpu_stat():
    cpuinfo = {}
    flag = 0
    f = open('/proc/cpuinfo')
    lines = f.readlines()
    f.close()
    logging.debug('get_cpu_stat() in utils/utility.py ')
    for line in lines:
        if len(line) < 2:
            continue
        name = line.split(':')[0].rstrip()
        if name == 'cpu cores':
            flag = 1
        var = line.split(':')[1].rstrip('\n')
        cpuinfo[name] = var
    if flag == 0:
        cpuinfo['cpu cores'] = '1'
    logging.debug('cpuName:%s,cpuFrequenc:%s cpuCores:%d\n'% (cpuinfo['model name'],cpuinfo['cpu MHz'],int(cpuinfo['cpu cores'])))
    return cpuinfo

def get_current_cpu_usage():
    """Read the current system cpu usage from /proc/stat."""  
    fd=None
    lines = []
    try:  
        fd = open("/proc/stat", 'r')  
        lines = fd.readlines()  
    finally:  
        if fd!=None:  
            fd.close()  
    for line in lines:  
        l = line.split()  
        if len(l) < 5:  
            continue  
        if l[0].startswith('cpu'):  
            return l 
    return []  
      
def get_current_cpuUtilization():
    """ 
    get cpu avg used by percent 
    """  
    cpustr = get_current_cpu_usage()  
    if cpustr==None or len(cpustr)==0:
        logging.error('get_current_cpuUtilization is error')  
        return 0  
    #cpu usage=[(user_2 +sys_2+nice_2) - (user_1 + sys_1+nice_1)]/(total_2 - total_1)*100  
    usni1 = float(cpustr[1])+float(cpustr[2])+float(cpustr[3])+float(cpustr[5])+float(cpustr[6])+float(cpustr[7])+float(cpustr[4])  
    usn1 = float(cpustr[1])+float(cpustr[2])+float(cpustr[3])  
    #usni1=long(cpustr[1])+long(cpustr[2])+long(cpustr[3])+long(cpustr[4])  
    sleep = 1  
    time.sleep(sleep)  
    cpustr = get_current_cpu_usage()  
    if cpustr==None or len(cpustr)==0:
        logging.error('get_current_cpuUtilization is error')      
        return 0  
    usni2 = float(cpustr[1])+float(cpustr[2])+float(cpustr[3])+float(cpustr[5])+float(cpustr[6])+float(cpustr[7])+float(cpustr[4])  
    usn2 = float(cpustr[1])+float(cpustr[2])+long(cpustr[3])  
    cpuper = (usn2-usn1)/(usni2-usni1)
    logging.debug('cpuUtilization:%d \n'% int(100*cpuper))
    return int(100*cpuper)
    
    
def get_current_memory_stat():
    mem = {}
    f = open('/proc/meminfo')
    lines = f.readlines()
    f.close()
    logging.debug('memory_stat() in /utils/utility.py')
    for line in lines:
        if len(line) < 2:
            continue
        name = line.split(':')[0]
        var = line.split(':')[1].split()[0]
        mem[name] = long(var)
    mem['MemUsed'] = long(mem['MemTotal'] - mem['MemFree'] - mem['Buffers'] - mem['Cached'])
    mem['MemFree'] = long(mem['MemTotal'] - mem['MemUsed'])
    mem['MemTotal'] = long(mem['MemTotal'])
    return mem



def get_current_disk_stat():
    hd = {}
    disk = os.statvfs('/')
    hd['available'] = long(disk.f_bsize * disk.f_bavail)
    hd['capacity'] = long(disk.f_bsize * disk.f_blocks)
    hd['used'] = hd['capacity'] - hd['available']
    return hd

def get_current_net_rate():
    """
    get net netReceiveRate ,netSendRate
    """
    recv=None
    send=None
    fd = open("/proc/net/dev", "r")  
    for line in fd.readlines():  
        if line.find("eth0") > 0:  
            field = line.split()
            logging.debug('get_current_net_rate:%s' %str(field))  
            recv = field[1]  
            send = field[9]  
    fd.close()
    logging.debug('recv: %s send:%s' %(recv,send))
    return (long(recv),long(send)) 

def get_cpu_num():
    status = '1'
    cmd_line = "cat /proc/cpuinfo |grep processor | wc -l"
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    if(cmd_status == 0):
        status = cmd_output
    return status

def utility_get_current_resource():
    """
    get cpu resource
    """
    logging.debug(' utility_get_current_resource()')
    hdSource = thd_hard_source()
    cpu = get_current_cpu_stat()
    hdSource.cpu_style = cpu['model name']
    hdSource.cpu_frequenc = cpu['cpu MHz']
    hdSource.cpu_num = int(get_cpu_num())
    logging.debug('cpuName:%s,cpuFrequenc:%s,cpuCores:%d\n'% (hdSource.cpu_style,hdSource.cpu_frequenc,hdSource.cpu_num))
        
    """
    get memory resource
    """
    memory = get_current_memory_stat()
    hdSource.total_memory = memory['MemTotal']
    hdSource.user_memory = memory['MemUsed']
    hdSource.free_memory = memory['MemFree']
    logging.debug('memTotal:%d,memUsed:%d,memFree:%d\n'%(hdSource.total_memory,hdSource.user_memory,hdSource.free_memory))
    """
    get disk resource
    """
    disk = get_current_disk_stat()
    hdSource.total_disk = disk['capacity']
    hdSource.user_disk = disk['used']
    hdSource.free_disk = disk['available']
    logging.debug('diskTotal:%d,diskUsed:%d,diskFree:%d\n'%(hdSource.total_disk,hdSource.user_disk,hdSource.free_disk))
    """
    get ip address resource
    """
    IP = get_local_publicip()
    if IP != None:
        hdSource.ip_address = IP
        logging.debug('pulicIP:%s'%hdSource.ip_address)
    return hdSource
    
    

def p_get_net_rate():
    """
    get netRate
    """ 
    recv,send = get_current_net_rate()
    time.sleep(1)  
    (new_recv, new_send) = get_current_net_rate()
    recvRate = new_recv -recv
    sendRate = new_send - send
    logging.debug('recvRate:%dB/S, sendRate: %dB/S'%(recvRate,sendRate))
    return recvRate, sendRate


def p_register_service(serviceName,hostIp,clusterName=None):
    if serviceName==None or hostIp==None:
        return -1
    if serviceName=='eucalyptus-cc' and clusterName==None:
        return -2	
    ret = 0
    cmd_line = None
    if serviceName=='eucalyptus-cc':
        cmd_line = 'sudo euca_conf --register-cluster '+clusterName+' '+hostIp
    if serviceName=='eucalyptus-walrus':
        cmd_line = 'sudo euca_conf --register-walrus '+hostIp
    if serviceName=='eucalyptus-nc':
        cmd_line = 'sudo euca_conf --register-nodes '+hostIp
    if cmd_line==None:
        return -3
    logging.info('p_register_service:%s' % cmd_line)	
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logging.info('p_register_service:%s' % cmd_output)
    if cmd_status == 0:
        ret = 0
    else:
        ret = -4
    return ret

def p_deregister_service(serviceName,parameter):
    if serviceName==None or parameter==None:
        return -1
    ret = -2
    cmd_line = None
    if serviceName=='eucalyptus-cc':
        cmd_line = 'sudo euca_conf --deregister-cluster '+parameter
    if serviceName=='eucalyptus-walrus':
		cmd_line = 'sudo euca_conf --deregister-walrus '+parameter
    if serviceName=='eucalyptus-nc':
		cmd_line = 'sudo euca_conf --deregister-nodes '+parameter
    if cmd_line==None:
        return -2
    logging.info('p_deregister_service: %s' % cmd_line)
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    logging.info('p_deregister_service: %s' % cmd_output)
    if cmd_status == 0:
        ret = 0
    else:
        ret = -3
    return ret

def indent_xml(dom, node, indent = 0):
    # Copy child list because it will change soon
    children = node.childNodes[:]
    # Main node doesn't need to be indented
    if indent:
        text = dom.createTextNode('\n' + '\t' * indent)
        node.parentNode.insertBefore(text, node)
    if children:
        # Append newline after last child, except for text nodes
        if children[-1].nodeType == node.ELEMENT_NODE:
            text = dom.createTextNode('\n' + '\t' * indent)
            node.appendChild(text)
            # Indent children which are elements
            for n in children:
                if n.nodeType == node.ELEMENT_NODE:
                     indent_xml(dom, n, indent + 1)

	
def write_xml_file(xmldom,xmlfile):
    domcopy = xmldom.cloneNode(True)
    indent_xml(domcopy, domcopy.documentElement)
    f=file(xmlfile,'w')
    writer = codecs.lookup('utf-8')[3](f)
    domcopy.writexml(writer, encoding = 'utf-8')
    domcopy.unlink()
    writer.close()

def remove_file(destfile):
	if os.path.exists(destfile):
		os.remove(destfile)
		logging.info('remove %s' % (destfile))	

def get_logger_level():
    fh = os.popen ('cat '+LDAP_CONF_FILE)
    str_level=None
    log_level = logging.WARNING
    for ln in fh.readlines ():
        if 'LOG_LEVEL' in ln:
            ls = ln.split('"')
            str_level = ls[1]
            break          
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
    return log_level

def init_log():
    logger = logging.getLogger('')
    ch = logging.handlers.RotatingFileHandler(LOG_FILE_ERROR, maxBytes=MAX_LOGFILE_BYTE, backupCount=5)
    formatter = logging.Formatter('<%(asctime)s> <%(levelname)s> <%(module)s:%(lineno)d>\t%(message)s', datefmt='%F %T')
    ch.setFormatter(formatter)
    ch.setLevel(logging.ERROR)
    dh = logging.handlers.RotatingFileHandler(LOG_FILE_WARN, maxBytes=MAX_LOGFILE_BYTE, backupCount=5)
    dh.setFormatter(formatter)
    dh.setLevel(logging.WARNING)
    ih = logging.handlers.RotatingFileHandler(LOG_FILE_INFO, maxBytes=MAX_LOGFILE_BYTE, backupCount=5)
    ih.setFormatter(formatter)
    ih.setLevel(logging.INFO)
    eh = logging.handlers.RotatingFileHandler(LOG_FILE_DEBUG, maxBytes=MAX_LOGFILE_BYTE, backupCount=5)
    eh.setFormatter(formatter)
    eh.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    logger.addHandler(ih)
    logger.addHandler(dh)
    logger.addHandler(eh)
    log_level = get_logger_level()
    logger.setLevel(log_level)  
    return logger



def get_ldap_server():
    fh = os.popen ('cat '+LDAP_CONF_FILE)
    ldap_server=None
    for ln in fh.readlines ():
        if 'LDAP_SERVER' in ln:
            ls = ln.split('"')
            ldap_server = ls[1]
            break
    return ldap_server

def get_real_ldap():
    fh = os.popen ('cat '+REAL_LDAP_CONF_FILE)
    ldap_server=None
    for ln in fh.readlines ():
        if 'LDAP_SERVER' in ln:
            ls = ln.split('"')
            ldap_server = ls[1]
            break
    return ldap_server

def get_local_publicip():
    ldapip = get_ldap_server()
    hostip=None
    if ldapip!=None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ldapip,80))
        hostip = s.getsockname()[0]
        s.close()
    return hostip


def p_is_service_start(serviceName):
    ret = False
    cmd_line = 'sudo service '+ serviceName + ' status'
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    if cmd_status == 0:
        if cmd_output.find('running')>-1:
	    ret = True
    return ret
	
def p_start_service(serviceName):
    cmd_line = None
    if p_is_service_start(serviceName) :
        cmd_line = 	'sudo service '+ serviceName + ' restart'	
    else:
	cmd_line = 'sudo service '+ serviceName + ' start'
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    if cmd_status == 0:
        return True
    else:
        return False

def p_stop_service(serviceName):
    ret = True
    cmd_line = None
    if p_is_service_start(serviceName) :
        cmd_line = 'sudo service '+ serviceName + ' stop'	
        cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
        if cmd_status != 0:
            ret = False        
    return ret

def get_image_upload_progress(ldap_ip,newImageId,newImageLen):
    progress = -1
    imageLength = p_getImageLength(ldap_ip,newImageId)
    logging.debug('get_image_upload_progress imageLength:%d' %imageLength)
    if imageLength>=0:
        progress = int(imageLength*100/newImageLen)
    return progress    

def make_easy_tag(dom, tagname, value, type='text'):
    tag = dom.createElement(tagname)
    if value.find(']]>') > -1:
        type = 'text'
    if type == 'text':
        value = value.replace('&', '&amp;')
        value = value.replace('<', '&lt;')
        text = dom.createTextNode(value)
    elif type == 'cdata':
        text = dom.createCDATASection(value)
    tag.appendChild(text)
    return tag
