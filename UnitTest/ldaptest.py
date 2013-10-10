import sys

sys.path.append("./gen-py")
sys.path.append("/usr/lib/python2.6/site-packages")

import chardet

import ldap
import ldap.modlist as modlist
import getopt, sys, os, stat
import hashlib
import base64
import time
import pexpect
import string
import uuid
import threading
import commands

import inspect
import ctypes

from CloudbotWebManagement.ttypes import *

VM_CONFIG_BASEDN = 'ou=virtualmachineconfig,cn=clc,o=cloudbot,o=sinobot'
USER_INFO_BASEDN = 'ou=zjut,o=cloudbot,o=sinobot'
PREFRENCE_BASEDN = 'ou=prefrencePrompt,cn=clc,o=cloudbot,o=sinobot'
AUTH_INFO_BASEDN = 'ou=auth_info,ou=auth_user,o=cloudbot,o=sinobot'
FEATURL_CONTROL_BASEDN = 'ou=featureControl,o=cloudbot,o=sinobot'
DEPARTMENT_BASEDN = 'ou=seriesname,cn=clc,o=cloudbot,o=sinobot'
WALRUS_CONFIG_BASEDN = 'ou=walrusconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot'
WALRUS_INFO_BASEDN = 'ou=WalrusInfo,ou=eucawalrus,cn=clc,o=cloudbot,o=sinobot'
IMAGE_BASEDN = 'ou=images, cn=clc, o=cloudbot, o=sinobot'
SYSTEM_BASEDN = 'o=cloudbot, o=sinobot'
EUCA_CONFIG_BASEDN = 'ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot'
CLUSTER_CONFIG_BASEDN = 'ou=clusterconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
NODE_CONFIG_BASEDN = 'ou=nodeconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
WEB_CONFIG_BASEDN = 'ou=webconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
CLC_BASEDN = 'cn=clc, o=cloudbot, o=sinobot'
IMAGE_STYLE_BASEDN = 'ou=ImageStyle,cn=clc,o=cloudbot,o=sinobot'
OSNAME_BASEDN = 'ou=OSName,cn=clc,o=cloudbot,o=sinobot'
FEATURE_ON = 'on'

DEFAULT_PASS = 'luhya'
ALL_MEAN = 'all'

BUFF_LEN = 1024*1024

g_backupFile ={}
g_backupFile['thread'] = None
BACKUP_ROOT_PATH = '/var/lib/eucalyptus/backup/'

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


def p_login_ldap(ldapip, username, password):
    l = None
    try:
        l = ldap.open(ldapip)
        l.protocol_version = ldap.VERSION3
        l.simple_bind(username, password)
    except  ldap.LDAPError, e:
        print e
        l = None
    return l


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


def p_get_resultSet_from_ldap(ldapip, username, password, baseDN, searchFilter, attrIDList):
    curldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    result_set = []
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
        print "error: %s" % e
        result_set = []
    return result_set


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


def p_euca_get_departmentId_by_department(depart):
    departId = -1
    seriesRes = p_get_resultSet_from_ldap('192.168.99.148', 'cn=admin,o=cloudbot,o=sinobot', 'ldap4$',
                                          'ou=seriesname,cn=clc,o=cloudbot,o=sinobot', 'cn=*', None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        id = 0
        for series in seriesRes:
            if(series[0][1].get('cn') != None):
                seriesName = series[0][1].get('cn')[0]
                print seriesName
                if(seriesName == depart):
                    departId = id
                    break
        id = id + 1
    return  departId


def add_ldap(newDN, attrs):
    l = p_login_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$")
    ldif = modlist.addModlist(attrs)
    l.add_s(newDN, ldif)
    l.unbind_s()


def test_get_depart():
    res = p_get_resultSet_from_ldap('192.168.99.8', 'CN=administrator,CN=Users,DC=pcbot,DC=biz', 'password1!',
                                    'CN=Users,DC=pcbot,DC=biz', "CN=harrison.liu", None)
    if (len(res) > 0 and len(res[0][0][1]) > 0):
        for userInfo in res:
            print userInfo
            if userInfo[0][1].get('department') != None:
                print userInfo[0][1].get('department')[0]
                depart = userInfo[0][1].get('department')[0]
                print depart
                departId = p_euca_get_departmentId_by_department(depart)
                print "departId is : %d" % departId


def p_euca_get_first_department():
    seriesName = None
    seriesRes = p_get_resultSet_from_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$",
                                          'ou=seriesname,cn=clc,o=cloudbot,o=sinobot', 'cn=*', None)
    if(len(seriesRes) > 0 and len(seriesRes[0][0][1]) > 0):
        for series in seriesRes:
            if(series[0][1].get('cn') != None):
                seriesName = series[0][1].get('cn')[0]
                print seriesName
            break
    return  seriesName


def write_to_file():
    fh = open('/root/prefrence.txt', 'a')
    fh.write('\xe6\x9c\xac\xe5\x9c\xb0\xe8\xbf\x9e\xe6\x8e\xa5')
    fh.write('\r\n')
    fh.write('#####sdfsdfsddsfsdf')
    fh.write('\r\n')
    fh.write('&&&&&&sdfsdfsddsfsdf')
    fh.write('\r\n')
    fh.close()


def get_ad_user():
    username = 'CN=administrator,CN=Users,DC=pcbot,DC=biz'
    userRes = p_get_resultSet_from_ldap('192.168.99.8', username, 'password1!', 'CN=Users,DC=pcbot,DC=biz', 'CN=*',
                                        None)
    if len(userRes) > 0 and len(userRes[0][0][1]) > 0:
        for user in userRes:
            if(user[0][1].get('givenName') != None):
                print user[0][1].get('cn')[0]


def ldap_search_entry(baseDN, attrIDList, Filters, scope):
    l = p_login_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$")
    searchScope = scope
    searchFilter = Filters
    retvalue = {}
    try:
        ldap_result_id = l.search(baseDN, searchScope, searchFilter, attrIDList)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
            #print "search net result:",  result_set
        if len(result_set) > 0 and len(result_set[0][0][1]) > 0:
            #print " --- ldap search find value", result_set[0][0][1]
            if attrIDList is None:
                attrIDList = result_set[0][0][1].keys()
            for attr in attrIDList:
                retvalue[attr] = result_set[0][0][1].get(attr)
    except ldap.LDAPError, e:
        print "--- ldap search error"
        retvalue = {}
    print  'last result:', retvalue
    return retvalue


def ldap_modify_entry(modifyDN, oldattrs, newattrs, ignore_attr_types=None, ignore_oldexistent=0):
    l = p_login_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$")
    ldif = modlist.modifyModlist(oldattrs, newattrs, ignore_attr_types, ignore_oldexistent)
    l.modify_s(modifyDN, ldif)
    l.unbind_s()


def p_get_value_set_from_ldap(ldapip, username, password, baseDN, searchFilter, key):
    ncldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    retrieveAttributes = None
    resValue = None
    if (ncldap != None):
        try:
            ldap_result_id = ncldap.search(baseDN, searchScope, searchFilter, retrieveAttributes)
            result_set = []
            result_type, result_data = ncldap.result(ldap_result_id, 0)
            print result_data
            if (result_data != None):
                result_set.append(result_data)
            for l in result_set:
                if(l != None):
                    for ll in l:
                        lll = ll[1]
                        if lll.has_key(key):
                            resValue = lll.get(key)
                            break
        except ldap.LDAPError, e:
            return None
        ncldap.unbind_s()
    return resValue


def sshcopy():
    src = 'root@192.168.99.147:/root/vmtest/machine'
    dst = '/root/pytest/'

    copy_cmd = "scp " + src + " " + dst
    ssh_newkey = "Are you sure you want to continue connecting"
    p = pexpect.spawn(copy_cmd)
    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 0:
        print "I say yes"
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline("12345")
        p.expect(pexpect.EOF)
    elif i == 2:
        print "I either got key or connection timeout"
    pass

#sshcopy()

def do_scp_from_remote_host(user, password, remotehost, remotefile, localpath):
    src = user + "@" + remotehost + ":" + remotefile
    dst = localpath
    copy_cmd = "scp " + src + " " + dst
    print copy_cmd
    ssh_newkey = "Are you sure you want to continue connecting"
    p = pexpect.spawn(copy_cmd, timeout=None)
    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 0:
        print "I say yes"
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
    #        print "I give password"
        p.sendline(password)
        p.expect(pexpect.EOF)
    elif i == 2:
        print "I either got key or connection timeout"
    pass


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
                popedom = string.atoi(userInfo[0][1].get('popedom')[0])
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
            if popedom == 2:
                isAdministrator = True
            passwordExpires = 0
            if userInfo[0][1].get('passwordExpires') != None:
                passwordExpires = string.atoi(userInfo[0][1].get('passwordExpires')[0])
            sLogonName = None
            if userInfo[0][1].get('employeeNumber') != None:
                sLogonName = userInfo[0][1].get('employeeNumber')[0]
            sSeriesName = None
            if userInfo[0][1].get('seriesNAME') != None:
                sSeriesName = userInfo[0][1].get('seriesNAME')[0]
            seriesID = 0
            if userInfo[0][1].get('seriesID') != None:
                seriesID = string.atoi(userInfo[0][1].get('seriesID')[0])
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
                seriesID=seriesID)
            usetList.append(user)
    return usetList


def p_get_ldap_info():
    return "192.168.99.180", "cn=admin,o=cloudbot,o=sinobot", "ldap4$"


def p_get_users_by_department(department):
    users = []
    ldapip, username, password = p_get_ldap_info()
    userlist = p_getUserList(ldapip, username, password, USER_INFO_BSDEDN, 'UserNAME=*')
    for userInfo in userlist:
        if(userInfo.sSeriesName == department ):
            users.append(userInfo)
    return users


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
        nodeInfo = thd_NodeInfo(\
            hostIp=hostIp,\
            clusterName=clusterName,\
            freeCPUs=freeCPUs,\
            freeDisk=freeDisk,\
            freeMem=freeMem,\
            totalCPUs=totalCPUs,\
            totalDisk=totalDisk,\
            totalMem=totalMem)
        nodeList.append(nodeInfo)
    return nodeList


def p_get_vmconfig_from_res(coninfo):
    if(coninfo == None):
        return None
    vmConfig = thd_vmConfig()
    vmConfig.id = coninfo[0][1].get('cn')[0]
    if(coninfo[0][1].get('UserNAME') != None ):
        vmConfig.user = coninfo[0][1].get('UserNAME')[0]
        ldapip, username, password = p_get_ldap_info()
        domain = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + vmConfig.user, 'domain')
        if(domain != None):
            vmConfig.domain = domain
        depart = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + vmConfig.user, 'seriesID')
        if(depart != None):
            vmConfig.departmentID = int(depart)
    if(coninfo[0][1].get('imageId') != None ):
        vmConfig.imageId = coninfo[0][1].get('imageId')[0]
    if(coninfo[0][1].get('machinename') != None):
        vmConfig.machinename = coninfo[0][1].get('machinename')[0]
    if(coninfo[0][1].get('isAssignNode') != None ):
        if(cmp(coninfo[0][1].get('isAssignNode')[0].lower(), 'true') == 0 ):
            vmConfig.isAssignNode = True
        else:
            vmConfig.isAssignNode = False
    if(coninfo[0][1].get('nodeIp') != None ):
        vmConfig.nodeIp = coninfo[0][1].get('nodeIp')[0]
    if(coninfo[0][1].get('publicIp') != None ):
        vmConfig.publicIp = coninfo[0][1].get('publicIp')[0]
    if(coninfo[0][1].get('publicMac') != None):
        vmConfig.publicMac = coninfo[0][1].get('publicMac')[0]
    if(coninfo[0][1].get('vmcpuNum') != None):
        vmConfig.vmcpuNum = int(coninfo[0][1].get('vmcpuNum')[0])
    if(coninfo[0][1].get('vmdisk') != None):
        vmConfig.vmdisk = int(coninfo[0][1].get('vmdisk')[0])
    if(coninfo[0][1].get('vmmemory') != None):
        vmConfig.vmmemory = int(coninfo[0][1].get('vmmemory')[0])
    if(coninfo[0][1].get('gateway') != None):
        vmConfig.gateway = coninfo[0][1].get('gateway')[0]
    if(coninfo[0][1].get('connName') != None):
        vmConfig.connName = coninfo[0][1].get('connName')[0]
    if(coninfo[0][1].get('netmask') != None):
        vmConfig.netmask = coninfo[0][1].get('netmask')[0]
    if(coninfo[0][1].get('dnsDomain') != None):
        vmConfig.dnsDomain = coninfo[0][1].get('dnsDomain')[0]
    if(coninfo[0][1].get('wins') != None):
        vmConfig.wins = coninfo[0][1].get('wins')[0]
    if(coninfo[0][1].get('isExtDisk') != None ):
        if( cmp(coninfo[0][1].get('isExtDisk')[0].lower(), 'true') == 0):
            vmConfig.isExtDisk = True
        else:
            vmConfig.isExtDisk = False

    if(coninfo[0][1].get('extDisk') != None):
        vmConfig.extDisk = int(coninfo[0][1].get('extDisk')[0])
    if(coninfo[0][1].get('thermophoresisNode') != None):
        vmConfig.thermophoresisNode = coninfo[0][1].get('thermophoresisNode')[0]
        nodeinfo = p_get_nodeinfo_by_nodeIp(vmConfig.thermophoresisNode)
    #    if(nodeinfo!=None):
    #      vmConfig.thermophoresisCluster= nodeinfo.clusterName
    if(coninfo[0][1].get('isThermophoresis') != None ):
        if( cmp(coninfo[0][1].get('isThermophoresis')[0].lower(), 'true') == 0):
            vmConfig.isThermophoresis = True
        else:
            vmConfig.isThermophoresis = False
    if(coninfo[0][1].get('isSnapshot') != None ):
        if( cmp(coninfo[0][1].get('isSnapshot')[0].lower(), 'true') == 0):
            vmConfig.isSnapshot = True
        else:
            vmConfig.isSnapshot = False
    if(coninfo[0][1].get('maxSnapshot') != None):
        vmConfig.maxSnapshot = int(coninfo[0][1].get('maxSnapshot')[0])
    if(coninfo[0][1].get('isSupportUsb') != None ):
        if( cmp(coninfo[0][1].get('isSupportUsb')[0].lower(), 'true') == 0):
            vmConfig.isSupportUsb = True
        else:
            vmConfig.isSupportUsb = False
    if(coninfo[0][1].get('isSupportParallel') != None ):
        if( cmp(coninfo[0][1].get('isSupportParallel')[0].lower(), 'true') == 0):
            vmConfig.isSupportParallel = True
        else:
            vmConfig.isSupportParallel = False
    if(coninfo[0][1].get('isDHCP') != None ):
        if( cmp(coninfo[0][1].get('isDHCP')[0].lower(), 'true') == 0):
            vmConfig.isDHCP = True
        else:
            vmConfig.isDHCP = False
    print  vmConfig
    return vmConfig


def get_container_by_department(department):
    if(department == None):
        return None
    container = p_get_value_from_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$", VM_CONFIG_BASEDN,
                                      'hostname=' + department, 'ou')
    return container

def p_euca_get_vmconfig_by_usrhost(preVmConfig):
    vmConfig = None
    ldapip, username, password = p_get_ldap_info()   
    baseDN = 'ou=default,' + VM_CONFIG_BASEDN
    res = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=*', None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for coninfo in res:
            if(coninfo[0][1].get('nodeIp') != None) and (coninfo[0][1].get('nodeIp')==preVmConfig.nodeIp) and (coninfo[0][1].get('UserNAME') != None) and ( coninfo[0][1].get('UserNAME')==preVmConfig.user):
                vmConfig = p_get_vmconfig_from_res(coninfo)
                vmConfig.departmentID = -1
                break
    return vmConfig
    
def p_euca_get_vmconfig_by_usrimg(preVmConfig):
    vmConfig = None
    department = p_get_value_from_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$", USER_INFO_BASEDN,
                                       'cn=' + preVmConfig.user, 'seriesNAME')
    print department
    container = None
    if(department != None):
        container = get_container_by_department(department)
        if(container == None):
            container = 'default'
    else:
        container = 'default'
    print container
    baseDN = 'ou=' + container + ',' + VM_CONFIG_BASEDN
    res = p_get_resultSet_from_ldap("192.168.99.148", "cn=admin,o=cloudbot,o=sinobot", "ldap4$", baseDN, 'cn=*', None)
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for coninfo in res:
            if((coninfo[0][1].get('imageId') != None and coninfo[0][1].get('imageId')[0] == preVmConfig.imageId )) and (
            (coninfo[0][1].get('UserNAME') != None and coninfo[0][1].get('UserNAME')[0] == preVmConfig.user )):
                vmConfig = p_get_vmconfig_from_res(coninfo)
                break
    return vmConfig


def p_get_vmconfig_by_node(nodeIp):
    vmConfigList = []
    if(nodeIp == None):
        return vmConfigList
    vmcfgList = p_get_all_vmconfig()
    if cmp(nodeIp.lower(), ALL_MEAN) == 0:
        return vmcfgList
    if(len(vmcfgList) > 0):
        for vmconfig in vmcfgList:
            if (vmconfig.nodeIp == nodeIp ):
                vmConfigList.append(vmconfig)
    return vmConfigList


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
            print e
        l.unbind_s()
    return ret


def p_get_vmconfig_by_cluster(clusterName):
    vmConfigList = []
    ldapip, username, password = p_get_ldap_info()
    nodelist = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'pcc=' + clusterName)
    vmcfgList = p_get_all_vmconfig()
    for vmconfig in vmcfgList:
        for nodeInfo in nodelist:
            if (vmconfig.nodeIp == nodeInfo.hostIp ):
                vmConfigList.append(vmconfig)
    return vmConfigList


def p_add_default_container():
    ret = True
    container = 'default'
    ldapip, username, password = p_get_ldap_info()
    strou = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'ou=' + container, 'ou')
    print strou
    if(strou == None):
        newConDN = 'ou=' + container + ',' + VM_CONFIG_BASEDN
        attrsCon = {}
        attrsCon['objectClass'] = 'EUCACONTAINER'
        attrsCon['hostname'] = 'default'
        ret = p_add_to_ldap(newConDN, attrsCon)
    return ret


def p_add_vmconfig_to_ldap(vmConfig):
    ret = False
    container = None
    if(p_get_vm_privacy()==1):
        container = 'default'
        ret = p_add_default_container()
        if(not ret):
            return False	
	else:
		ldapip, username, password = p_get_ldap_info()
		department = None
		if(vmConfig.departmentID != None):
			if(vmConfig.departmentID != -1):
				department = p_euca_get_department_by_id(vmConfig.departmentID)
		else:
			if(vmConfig.user != None and vmConfig.user != 'any'):
				department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + vmConfig.user,
												   'seriesNAME')
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
				if(not ret):
					return ret
		else:
			container = 'default'
			ret = p_add_default_container()
			if(not ret):
				return False
    
    
    attrs = {}
    cn = str(uuid.uuid4())
    attrs['objectClass'] = 'VMCONFIG'
    attrs['cn'] = cn
    attrs['UserNAME'] = vmConfig.user
    attrs['imageId'] = vmConfig.imageId
    if(vmConfig.domain != None):
        attrs['domain'] = vmConfig.domain
    if(vmConfig.machinename != None):
        attrs['machinename'] = vmConfig.machinename
    if(vmConfig.publicIp != None):
        attrs['publicIp'] = vmConfig.publicIp
    if(vmConfig.publicMac != None):
        attrs['publicMac'] = vmConfig.publicMac
    if(vmConfig.vmcpuNum != None):
        attrs['vmcpuNum'] = str(vmConfig.vmcpuNum)
    if(vmConfig.vmmemory != None):
        attrs['vmmemory'] = str(vmConfig.vmmemory)
    if(vmConfig.vmdisk != None):
        attrs['vmdisk'] = str(vmConfig.vmdisk)
    if(vmConfig.isAssignNode != None):
        if(vmConfig.isAssignNode):
            attrs['isAssignNode'] = 'TRUE'
        else:
            attrs['isAssignNode'] = 'FALSE'
    if(vmConfig.nodeIp != None):
        attrs['nodeIp'] = vmConfig.nodeIp
    if(vmConfig.gateway != None):
        attrs['gateway'] = vmConfig.gateway
    if(vmConfig.connName != None):
        attrs['connName'] = vmConfig.connName
    if(vmConfig.netmask != None):
        attrs['netmask'] = vmConfig.netmask
    if(vmConfig.dnsDomain != None):
        attrs['dnsDomain'] = vmConfig.dnsDomain
    if(vmConfig.wins != None):
        attrs['wins'] = vmConfig.wins
    if(vmConfig.isExtDisk != None):
        if(vmConfig.isExtDisk):
            attrs['isExtDisk'] = 'TRUE'
        else:
            attrs['isExtDisk'] = 'FALSE'
    if(vmConfig.extDisk != None):
        attrs['extDisk'] = str(vmConfig.extDisk)
    if(vmConfig.isThermophoresis != None):
        if(vmConfig.isThermophoresis):
            attrs['isThermophoresis'] = 'TRUE'
        else:
            attrs['isThermophoresis'] = 'FALSE'
    if(vmConfig.isSnapshot != None):
        if(vmConfig.isSnapshot):
            attrs['isSnapshot'] = 'TRUE'
        else:
            attrs['isSnapshot'] = 'FALSE'
    if(vmConfig.maxSnapshot != None):
        attrs['maxSnapshot'] = str(vmConfig.maxSnapshot)
    if(vmConfig.isSupportUsb != None):
        if(vmConfig.isSupportUsb):
            attrs['isSupportUsb'] = 'TRUE'
        else:
            attrs['isSupportUsb'] = 'FALSE'
    if(vmConfig.isSupportParallel != None):
        if(vmConfig.isSupportParallel):
            attrs['isSupportParallel'] = 'TRUE'
        else:
            attrs['isSupportParallel'] = 'FALSE'
    if(vmConfig.isDHCP != None):
        if(vmConfig.isDHCP):
            attrs['isDHCP'] = 'TRUE'
        else:
            attrs['isDHCP'] = 'FALSE'
    if(vmConfig.thermophoresisNode != None):
        attrs['thermophoresisNode'] = vmConfig.thermophoresisNode
    if(vmConfig.isSupportPeripheral != None):
        if(vmConfig.isSupportPeripheral):
            attrs['isSupportPeripheral'] = 'TRUE'
        else:
            attrs['isSupportPeripheral'] = 'FALSE'

    newDN = 'cn=' + cn + ',ou=' + container + ',' + VM_CONFIG_BASEDN
    ret = p_add_to_ldap(newDN, attrs)
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
        print e
        ret = False
    ncldap.unbind_s()
    return ret


def p_update_vmconfig_info(vmConfig):
    if(vmConfig.user == 'any'):
        container = 'default'
    else:
        ldapip, username, password = p_get_ldap_info()
        department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + vmConfig.user,
                                           'seriesNAME')
        if(department != None):
            container = get_container_by_department(department)
        else:
            container = 'default'
    dn = 'cn=' + vmConfig.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN
    print dn
    list_attr = []
    if(vmConfig.user != None):
        attr = (ldap.MOD_REPLACE, 'UserNAME', vmConfig.user)
        list_attr.append(attr)
    if(vmConfig.imageId != None):
        attr = (ldap.MOD_REPLACE, 'imageId', vmConfig.imageId)
        list_attr.append(attr)
    if(vmConfig.domain != None):
        attr = (ldap.MOD_REPLACE, 'domain', vmConfig.domain)
        list_attr.append(attr)
    if(vmConfig.machinename != None):
        attr = (ldap.MOD_REPLACE, 'machinename', vmConfig.machinename)
        list_attr.append(attr)
    if(vmConfig.publicIp != None):
        attr = (ldap.MOD_REPLACE, 'publicIp', vmConfig.publicIp)
        list_attr.append(attr)
    if(vmConfig.publicMac != None):
        attr = (ldap.MOD_REPLACE, 'publicMac', vmConfig.publicMac)
        list_attr.append(attr)
    if(vmConfig.vmcpuNum != None):
        attr = (ldap.MOD_REPLACE, 'vmcpuNum', str(vmConfig.vmcpuNum))
        list_attr.append(attr)
    if(vmConfig.vmmemory != None):
        attr = (ldap.MOD_REPLACE, 'vmmemory', str(vmConfig.vmmemory))
        list_attr.append(attr)
    if(vmConfig.vmdisk != None):
        attr = (ldap.MOD_REPLACE, 'vmdisk', str(vmConfig.vmdisk))
        list_attr.append(attr)
    if(vmConfig.isAssignNode != None):
        attr = None
        if(vmConfig.isAssignNode):
            attr = (ldap.MOD_REPLACE, 'isAssignNode', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isAssignNode', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.nodeIp != None):
        attr = (ldap.MOD_REPLACE, 'nodeIp', vmConfig.nodeIp)
        list_attr.append(attr)
    if(vmConfig.gateway != None):
        attr = (ldap.MOD_REPLACE, 'gateway', vmConfig.gateway)
        list_attr.append(attr)
    if(vmConfig.connName != None):
        attr = (ldap.MOD_REPLACE, 'connName', vmConfig.connName)
        list_attr.append(attr)
    if(vmConfig.netmask != None):
        attr = (ldap.MOD_REPLACE, 'netmask', vmConfig.netmask)
        list_attr.append(attr)
    if(vmConfig.dnsDomain != None):
        attr = (ldap.MOD_REPLACE, 'dnsDomain', vmConfig.dnsDomain)
        list_attr.append(attr)
    if(vmConfig.wins != None):
        attr = (ldap.MOD_REPLACE, 'wins', vmConfig.wins)
        list_attr.append(attr)
    if(vmConfig.isExtDisk != None):
        attr = None
        if(vmConfig.isExtDisk):
            attr = (ldap.MOD_REPLACE, 'isExtDisk', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isExtDisk', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.extDisk != None):
        attr = (ldap.MOD_REPLACE, 'wins', str(vmConfig.extDisk))
        list_attr.append(attr)
    if(vmConfig.isThermophoresis != None):
        attr = None
        if(vmConfig.isThermophoresis):
            attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isThermophoresis', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.isSnapshot != None):
        attr = None
        if(vmConfig.isSnapshot):
            attr = (ldap.MOD_REPLACE, 'isSnapshot', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isSnapshot', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.maxSnapshot != None):
        attr = (ldap.MOD_REPLACE, 'wins', str(vmConfig.maxSnapshot))
        list_attr.append(attr)
    if(vmConfig.isSupportUsb != None):
        attr = None
        if(vmConfig.isSupportUsb):
            attr = (ldap.MOD_REPLACE, 'isSupportUsb', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isSupportUsb', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.isSupportParallel != None):
        attr = None
        if(vmConfig.isSupportParallel):
            attr = (ldap.MOD_REPLACE, 'isSupportParallel', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isSupportParallel', 'FALSE')
        list_attr.append(attr)
    if(vmConfig.isDHCP != None):
        attr = None
        if(vmConfig.isDHCP):
            attr = (ldap.MOD_REPLACE, 'isDHCP', 'TRUE')
        else:
            attr = (ldap.MOD_REPLACE, 'isDHCP', 'FALSE')
        list_attr.append(attr)
    return p_update_to_ldap(dn, list_attr)


def p_convert_to_new_vmconfig(oldConfig, vmConfig):
    if(vmConfig.user != None):
        oldConfig.user = vmConfig.user
    if(vmConfig.imageId != None):
        oldConfig.imageId = vmConfig.imageId
    if(vmConfig.domain != None):
        oldConfig.domain = vmConfig.domain
    if(vmConfig.machinename != None):
        oldConfig.machinename = vmConfig.machinename
    if(vmConfig.publicIp != None):
        oldConfig.publicIp = vmConfig.publicIp
    if(vmConfig.publicMac != None):
        oldConfig.publicMac = vmConfig.publicMac
    if(vmConfig.vmcpuNum != None):
        oldConfig.vmcpuNum = vmConfig.vmcpuNum
    if(vmConfig.vmmemory != None):
        oldConfig.vmmemory = vmConfig.vmmemory
    if(vmConfig.vmdisk != None):
        oldConfig.vmdisk = vmConfig.vmdisk
    if(vmConfig.isAssignNode != None):
        oldConfig.isAssignNode = vmConfig.isAssignNode
    if(vmConfig.nodeIp != None):
        oldConfig.nodeIp = vmConfig.nodeIp
    if(vmConfig.gateway != None):
        oldConfig.gateway = vmConfig.gateway
    if(vmConfig.connName != None):
        oldConfig.connName = vmConfig.connName
    if(vmConfig.netmask != None):
        oldConfig.netmask = vmConfig.netmask
    if(vmConfig.dnsDomain != None):
        oldConfig.dnsDomain = vmConfig.dnsDomain
    if(vmConfig.wins != None):
        oldConfig.wins = vmConfig.wins
    if(vmConfig.isExtDisk != None):
        oldConfig.isExtDisk = vmConfig.isExtDisk
    if(vmConfig.extDisk != None):
        oldConfig.extDisk = vmConfig.extDisk
    if(vmConfig.isThermophoresis != None):
        oldConfig.isThermophoresis = vmConfig.isThermophoresis
    if(vmConfig.isSnapshot != None):
        oldConfig.isSnapshot = vmConfig.isSnapshot
    if(vmConfig.maxSnapshot != None):
        oldConfig.maxSnapshot = vmConfig.maxSnapshot
    if(vmConfig.isSupportUsb != None):
        oldConfig.isSupportUsb = vmConfig.isSupportUsb
    if(vmConfig.isSupportParallel != None):
        oldConfig.isSupportParallel = vmConfig.isSupportParallel
    if(vmConfig.isDHCP != None):
        oldConfig.isDHCP = vmConfig.isDHCP
    if(vmConfig.thermophoresisNode != None):
        oldConfig.thermophoresisNode = vmConfig.thermophoresisNode
    return oldConfig


def p_change_vmconfig_to_ldap(vmConfig):
    ret = False
    if(vmConfig.id == None):
        return ret
    vm = p_get_vmconfig_by_id(vmConfig.id)
    if(vm == None):
        return ret
    if(vm.user == vmConfig.user or vmConfig.user == None):
        ret = p_update_vmconfig_info(vmConfig)
    else:
        ret = p_delete_vmconfig_from_ldap(vm)
        if(ret):
            newVmconfig = p_convert_to_new_vmconfig(vm, vmConfig)
            ret = p_add_vmconfig(newVmconfig)
    return ret


def p_get_vmconfig_by_id(id):
    vmConfig = None
    ldapip, username, password = p_get_ldap_info()
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    containList = []
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for cont in res:
            if cont[0][1].get('ou') != None:
                contain = cont[0][1].get('ou')[0]
                baseDN = 'ou=' + contain + ',' + VM_CONFIG_BASEDN
                configres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=' + id, None)
                if len(configres) > 0 and len(configres[0][0][1]) > 0:
                    vmConfig = p_get_vmconfig_from_res(configres[0])
                    if(contain == 'default'):
                        vmConfig.departmentID = -1
                    else:
                        vmConfig.departmentID = p_euca_get_departmentId_by_department(cont[0][1].get('hostname')[0])
                    break
    return  vmConfig


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


def p_euca_is_admin(userName):
    ldapip, username, password = p_get_ldap_info()
    popedom = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=userName', 'popedom')
    if (popedom == '2'):
        return True
    else:
        return False


def get_image(imageID):
    imageInfo = None
    ldapip, username, password = p_get_ldap_info()
    imgList = p_get_image_Infos(ldapip, username, password, IMAGE_BASEDN, 'imageId=' + imageID)
    if(imgList != None and len(imgList) > 0):
        imageInfo = imgList[0]
    print imageInfo
    return imageInfo


def p_euca_get_user_department_id(userName):
    departmentId = -1
    ldapip, username, password = p_get_ldap_info()
    department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=userName', 'seriesID')
    if(department != None):
        departmentId = int(department)
    return departmentId


def p_get_users_by_department(departmentID):
    users = []
    ldapip, username, password = p_get_ldap_info()
    userlist = p_getUserList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
    for userInfo in userlist:
        if(userInfo.sSeriesName != None) and (userInfo.seriesID != None) and ( userInfo.seriesID == departmentID ):
            users.append(userInfo)
    return users


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


def p_luhya_get_available_images_by_user(userName):
    images = []
    ldapip, username, password = p_get_ldap_info()
    domain = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'domain')
    print 'the domain is:%s' % domain
    img_list = p_euca_get_images_by_user(userName)
    if(domain != None):
        for image in img_list:
            print 'image list is : %s' % str(image)
            preVmConfig = thd_vmConfig(user=userName, imageId=image.imageId)
            vmconfig = p_euca_get_vmconfig_by_usrimg(preVmConfig)
            print 'the vm config is: %s' % str(vmconfig)
            if(vmconfig != None):
                images.append(image)
        return images
    else:
        return img_list


def p_get_nodeinfo_by_nodeIp(nodeIp):
    nodeInfo = None
    ldapip, username, password = p_get_ldap_info()
    list_info = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP=' + nodeIp)
    if(len(list_info) > 0):
        nodeInfo = list_info[0]
    return nodeInfo


def p_get_all_vmconfig():
    vmcfgList = []
    ldapip, username, password = p_get_ldap_info()
    res = p_get_resultSet_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'hostname=*', None)
    containList = []
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for contain in res:
            if contain[0][1].get('ou') != None:
                containList.append(contain[0][1].get('ou')[0])
    for contain in containList:
        baseDN = 'ou=' + contain + ',' + VM_CONFIG_BASEDN
        configres = p_get_resultSet_from_ldap(ldapip, username, password, baseDN, 'cn=*', None)
        if len(configres) > 0 and len(configres[0][0][1]) > 0:
            for configinfo in configres:
                vmConfig = p_get_vmconfig_from_res(configinfo)
                if(contain == 'default'):
                    vmConfig.departmentID = -1
                else:
                    department = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN, 'ou=' + contain,
                                                       'hostname')
                    vmConfig.departmentID = p_euca_get_departmentId_by_department(department)

                vmcfgList.append(vmConfig)
    return  vmcfgList


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


def p_get_user_name_list():
    ldapip, username, password = p_get_ldap_info()
    list_info = p_getUserNameList(ldapip, username, password, USER_INFO_BASEDN, 'UserNAME=*')
    return list_info


def p_delete_vmconfig_from_ldap(vmConfig):
    if(vmConfig.id == None):
        return False
    vm = p_get_vmconfig_by_id(vmConfig.id)
    print vm
    if(vm == None):
        return False
    container = None
    if(vm.user == None or vm.user == 'any'):
        container = 'default'
    else:
        department = p_get_department_by_user(vm.user)
        if(department == None):
            container = 'default'
        else:
            container = get_container_by_department(department)
    print container
    if(container == None):
        return False
    dn = 'cn=' + vmConfig.id + ',ou=' + container + ',' + VM_CONFIG_BASEDN
    print dn


def p_get_department_by_user(userName):
    ldapip, username, password = p_get_ldap_info()
    department = p_get_value_from_ldap(ldapip, username, password, USER_INFO_BASEDN, 'cn=' + userName, 'seriesNAME')
    return department


def p_get_nodeinfo_by_nodeIp(nodeIp):
    nodeInfo = None
    ldapip, username, password = p_get_ldap_info()
    list_info = p_getNodeList(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP=' + nodeIp)
    if(len(list_info) > 0):
        nodeInfo = list_info[0]
    return nodeInfo


def p_delete_to_ldap(dn):
    ldapip, username, password = p_get_ldap_info()
    ncldap = p_login_ldap(ldapip, username, password)
    if ncldap == None:
        return False
    try:
        ncldap.delete_s(dn)
        ret = True
    except ldap.LDAPError, e:
        ret = False
    ncldap.unbind_s()
    return ret


def p_euca_get_department_by_id(departid):
    seriesName = None
    if(departid == None or departid == -1):
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


def p_delete_vmconfig_by_node(nodeIp):
    vmList = []
    if(nodeIp == None):
        return False
    if(cmp(nodeIp.lower(), 'all') == 0):
        vmList = p_get_all_vmconfig()
    else:
        vmList = p_get_vmconfig_by_node(nodeIp)
    print vmList
    if(len(vmList) > 0):
        for vm in vmList:
            container = None
            if(vm.departmentID == None):
                if(vm.user == None or vm.user == 'any'):
                    container = 'default'
                else:
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
            p_delete_to_ldap(dn)
    return True


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
                            vmConfig.departmentID = -1
                        else:
                            department = p_get_value_from_ldap(ldapip, username, password, VM_CONFIG_BASEDN,
                                                               'ou=' + conname, 'hostname')
                            vmConfig.departmentID = p_euca_get_departmentId_by_department(department)
                        vmcfgList.append(vmConfig)
    print vmcfgList
    return  vmcfgList


#images = p_luhya_get_available_images_by_user('harrison.liu')

#print 'the user can user:%s' % str(images)

#m=hashlib.md5()
#m.update('\xe5\xbc\x80\xe5\x8f\x91\xe9\x83\xa8')
#strdep = m.hexdigest()
#print strdep
#users = p_get_users_by_department(0)
#print users

def p_get_resultSet_from_ldap_base(ldapip, username, password, baseDN, searchFilter, attrIDList):
    curldap = p_login_ldap(ldapip, username, password)
    searchScope = ldap.SCOPE_SUBTREE
    result_set = []
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
        print "error: %s" % e
        result_set = []
    return result_set


def update_vmconfig():
    dn = 'cn=1a506d29-3217-4868-8eb1-704ef3257a30,ou=2ed37a11fb0f006fe98d9f771e3ebe69,' + VM_CONFIG_BASEDN
    list_attr = []
    attr = (ldap.MOD_REPLACE, 'domain', None)
    list_attr.append(attr)
    print dn
    p_update_to_ldap(dn, list_attr)


def p_euca_add_user_info(userInfo):       # ou=zjut,o=cloudbot,o=sinobot      
    ret = False
    if(cmp(userInfo.userName.lower(), 'administrator') == 0 or cmp(userInfo.userName.lower(), 'admin') == 0):
        return ret
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
        attrs['employeeNumber'] = userInfo.sLogonName
        if(userInfo.isApproved):
            attrs['isApproved'] = 'TRUE'
        else:
            attrs['isApproved'] = "FALSE"
        if(userInfo.isConfirmed):
            attrs['isConfirmed'] = 'TRUE'
        else:
            attrs['isConfirmed'] = "FALSE"
        if(userInfo.isEnabled):
            attrs['isEnable'] = 'TRUE'
        else:
            attrs['isEnable'] = "FALSE"
        if(userInfo.isPrivateImgCreated):
            attrs['isPrivateImgCreated'] = 'TRUE'
        else:
            attrs['isPrivateImgCreated'] = "FALSE"
        attrs['popedom'] = str(userInfo.popedom)
        attrs['passwordExpires'] = str(userInfo.passwordExpires)
        attrs['uid'] = str(userInfo.reservationId)
        attrs['confirmetionCode'] = userInfo.confirmationCode
        attrs['certificateCode'] = userInfo.certificateCode
        attrs['domain'] = userInfo.domain

        print attrs
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


def p_euca_get_domain_info_from_ldap(domain):
    ldapip, username, password = p_get_ldap_info()
    domainlist = p_euca_get_domain_info(ldapip, username, password, PREFRENCE_BASEDN, 'cn=' + domain)
    if(len(domainlist) > 0):
        return domainlist[0]
    else:
        return None


def p_euca_is_department_exist(department):
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    depart = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, DEPARTMENT_BASEDN, 'cn=' + department, 'cn')
    if(depart == None):
        return False
    else:
        return True


def p_get_all_AD_user_info(domain):
    users = []
    domaininfo = p_euca_get_domain_info_from_ldap(domain)
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


def p_euca_is_user_exist(userName):
    ldapip, ldapusername, ldappassword = p_get_ldap_info()
    user = p_get_value_from_ldap(ldapip, ldapusername, ldappassword, USER_INFO_BASEDN, 'cn=' + userName, 'UserNAME')
    if(user == None):
        return False
    else:
        return True


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


def p_import_AD_users(domain):
    users = p_get_all_AD_user_info(domain)
    print users
    if(len(users) > 0):
        for userInfo in users:
            if(p_euca_add_user_info(userInfo)):
                p_euca_add_auth_user(userInfo)
    return


class p_import_AD_user_thread(threading.Thread):
    def __init__(self, domain):
        threading.Thread.__init__(self)
        self.domain = domain

    def run(self):
        print 'p_import_AD_user_thread starting ...'
        p_import_AD_users(self.domain)




def p_create_import_AD_user_thread(domain):
    processid = p_import_AD_user_thread(domain)
    processid.start()


def p_move_file(srcFile,decFile):
    cmd = 'mv ' + srcFile + ' ' + decFile
    cmd_status, cmd_output = commands.getstatusoutput(cmd)
    print 'p_move_file cmd_output:%s' % str(cmd_output)
    if cmd_status:
        print 'p_move_file  error'
        return -1
    return 0 
    
class p_backup_instance_thread(threading.Thread):
    def __init__(self,userName,imageID):
        threading.Thread.__init__(self)
        self.userName = userName
        self.imageID = imageID
        self.isTerminate = False
    def run(self):
        instanceId = (self.imageID[4:len(self.imageID)] + self.userName)[0:15]
        print 'p_backup_instance_thread  backup ins: %s' % instanceId
        backup_total_len = 0
        backup_cache_path = '/root/pytest/backup/'
        backup_cache_file = backup_cache_path+'machine'
        print 'p_backup_instance_thread  backup path: %s' % backup_cache_file
        if not os.path.exists(backup_cache_path):
            try:
                os.makedirs(backup_cache_path)
            except:
                print 'makedirs BACKUP_FAILED'
                return

        ins_cache_file = '/root/pytest/machine'
        if not os.path.exists(backup_cache_file):
            iflen = 0
            if os.path.exists(ins_cache_file):
                stat = os.stat(ins_cache_file)
                if(stat!=None):
                    iflen = stat.st_size
            backup_total_len =backup_total_len+ iflen
    
        ins_instance_file =  '/root/pytest/img/machine'
        if os.path.exists(ins_instance_file):
            slen = 0
            stat = os.stat(ins_instance_file)
            if(stat!=None):
                slen = stat.st_size
            backup_total_len =backup_total_len+ slen
			
        progress = 0
        is_backup_error = False
        if not os.path.exists(backup_cache_file) :
            fSource = open(ins_cache_file, 'rb')
            print 'p_backup_instance_thread  ins_cache_file: %s' % ins_cache_file
            try:  
                fSource.seek (0) 
                isBackupOver = False
                wrFile = backup_cache_path+'machine.tmp'      
                if(os.path.exists(wrFile)):
					os.remove(wrFile)			
                fDest = open(wrFile, 'a')
                try:
                    writelen = 0				
                    while True:
                        if self.isTerminate:
                            break   
                        buffer = fSource.read(BUFF_LEN)                       
                        if not buffer:
							# mv filer
                            isBackupOver = True                          
                            break
                        fDest.write(buffer)
                        writelen=writelen+BUFF_LEN
                        if writelen>backup_total_len:
						    writelen = backup_total_len
                        backup_cache_progress = int(writelen*100/backup_total_len)
                        if backup_cache_progress > progress :
							progress = backup_cache_progress
							print 'p_backup_instance_thread  progress: %s' % str(progress)               
                except Exception:
					is_backup_error = True
					print 'write file BACKUP_FAILED'
                fDest.close()
                if isBackupOver:
                    p_move_file(wrFile,backup_cache_file)
            except Exception:
				is_backup_error = True
				print '3 BACKUP_FAILED'
            fSource.close()           
        return

    def stop(self):
        self.isTerminate = True


class p_backup_instance(threading.Thread):
    def __init__(self,strPath):
        threading.Thread.__init__(self)
        self.file = strPath
        self.isTerminate = False
    def run(self):
        print 'copy starting'
        if(os.path.exists(self.file)):
            fSource = open(self.file, 'rb')
            try: 
                print 'source open:%s' % self.file 
                fSource.seek (0)       
                wrFile = '/root/pytest/machine'
                if(os.path.exists(wrFile)):
					os.remove(wrFile)			
                fDest = open(wrFile, 'a')
                try:
                    times = 0				
                    while True:
                        if self.isTerminate:
                            break   
                        buffer = fSource.read(BUFF_LEN)
                        
                        if not buffer:
                            print 'cannot read  fSource ' 
                            break
                        fDest.write(buffer)
                        times=times+BUFF_LEN
                        
                finally:
                    fDest.close()
            finally:
                 fSource.close()

    def stop(self):
		self.isTerminate = True


		
def p_get_vm_privacy():
    ldapip, username, password = p_get_ldap_info()
    vmPrivacy = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'vmPrivacy')
    privacy = 0
    if(vmPrivacy != None):
        privacy = int(vmPrivacy)       		
    return privacy  
 
 
def p_euca_get_vmconfig(preVmConfig):
    if(p_get_vm_privacy()==1):
        return p_euca_get_vmconfig_by_usrhost(preVmConfig)
    else:
        return p_euca_get_vmconfig_by_usrimg(preVmConfig)
          

def p_add_vmconfig(vmConfig):
    ret = False
    oldVmConfig = p_euca_get_vmconfig(vmConfig)
    if(oldVmConfig == None):
        ret = p_add_vmconfig_to_ldap(vmConfig)
    else:
        vmConfig.id = oldVmConfig.id
        ret = p_change_vmconfig_to_ldap(vmConfig)
    return ret      

g_myStr = None

def start_copy_thread(strFile):
    backupFile = p_backup_instance(strFile)
    g_backupFile['thread'] = backupFile
    g_backupFile['thread'].start()

def stop_copy_thread():	
    time.sleep(5)	
    if g_backupFile['thread']!=None:
        g_backupFile['thread'].stop()
    else:
		print 'g_backupFile is none'

#start_copy_thread('/root/admin/img/winxp-sp3.qcow2')
#stop_copy_thread()
def p_get_file_length( fileName):
    len = -1
    stat = os.stat(fileName)
    if(stat!=None):
        len = stat.st_size
    return len

 
def start_backup_thread():
    backupFile = p_backup_instance_thread('nyeo','emi-243DFC34C')
    g_backupFile['thread'] = backupFile
    g_backupFile['thread'].start()

def stop_backup_thread():	
    time.sleep(5)	
    if g_backupFile['thread']!=None:
        g_backupFile['thread'].stop()
    else:
		print 'g_backupFile is none'

def p_get_file_length( fileName):
    len = -1
    stat = os.stat(fileName)
    if(stat!=None):
        len = stat.st_size
    return len

def p_restore_file(backup_ins_file,ins_instance_file):
    if os.path.exists(backup_ins_file): 
        print  backup_ins_file
        backup_total_len = p_get_file_length(backup_ins_file)
        print backup_total_len
        fSource = open(backup_ins_file, 'rb')
        print  ins_instance_file
        progress = 0
        try:  
            fSource.seek (0) 			
            if(os.path.exists(ins_instance_file)):
                os.remove(ins_instance_file)
            print  '1'			
            fDest = open(ins_instance_file, 'a')
            print  '2'
            isRestoreOver = False
            try:
                writelen = 0				
                while True: 
                    buffer = fSource.read(BUFF_LEN)
                    print  '3'
                    if not buffer:
                        #mv file
                        isRestoreOver = True						
                        print 'RESTORE_FINISH'
                        break
                    fDest.write(buffer)
                    print  '4'
                    writelen=writelen+BUFF_LEN
                    if writelen>backup_total_len:
                        writelen = backup_total_len
                    backup_cache_progress = int(writelen*100/backup_total_len)
                    if backup_cache_progress > progress :
                        progress = backup_cache_progress
                        print 'p_restore_instance_thread  progress:%d' % progress
            except Exception:
                print 'RESTORE_FAILED 1'
            fDest.close()			
        except Exception:
            print 'RESTORE_FAILED 2'
        fSource.close()
        
def has_hz(text):
    hz_yes = False
    unStr = unicode(text, "utf-8")
    for uch in unStr:       
        if uch >= u'\u4e00' and uch<=u'\u9fa5' :
            hz_yes = True
            break   
    return hz_yes

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
 
def get_all_service_ip(): 
    ipList = []
    ldapip, username, password = p_get_ldap_info()
    ipList.append(ldapip)
    clcip = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
    print clcip
    if clcip!=None and clcip!=ldapip :
        ipList.append(clcip)
    res = p_get_resultSet_from_ldap(ldapip, username, password, EUCA_CONFIG_BASEDN, 'ou=*', None)   
    if len(res) > 0 and len(res[0][0][1]) > 0:
        for eucaConf in res:
            if eucaConf[0][1].get('ou') != None and eucaConf[0][1].get('ou')[0]!='eucaconfig':
                serviceName = eucaConf[0][1].get('ou')[0]
                baseDn = 'ou='+serviceName+','+EUCA_CONFIG_BASEDN
                print baseDn
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
        services.append('slapd')
    clcip = p_get_value_from_ldap(ldapip, username, password, CLC_BASEDN, 'cn=systemconfiguration', 'cloudHost')
    if ipAddress == clcip :
        services.append('eucalyptus-cloud')
    cluster = p_get_value_from_ldap(ldapip, username, password, CLUSTER_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'clusterName')    
    if cluster!=None :
        services.append('eucalyptus-cc')
    walrus = p_get_value_from_ldap(ldapip, username, password, WALRUS_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'walrusName')
    if walrus!=None :
        services.append('eucalyptus-walrus')
    nodeIp = p_get_value_from_ldap(ldapip, username, password, NODE_CONFIG_BASEDN, 'IP='+ipAddress, 'cn')		    
    if nodeIp!=None :
        services.append('eucalyptus-nc')
    webIp = p_get_value_from_ldap(ldapip, username, password, WEB_CONFIG_BASEDN, 'hostIPName='+ipAddress, 'hostIPName')		    
    if webIp!=None :
        services.append('cloudwebadmin')
    return services


def p_is_service_start(serviceName):
    cmd_line = 'service '+ serviceName + ' status'
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    print cmd_status
    print cmd_output    
    print cmd_output.find('running')

p_is_service_start('eucalyptus-cc')
#vm = p_euca_get_vmconfig_by_usrimg(vmconfig)
#print 'the vm config info is: %s' % str(vm)

#con = p_get_value_from_ldap("192.168.99.148","cn=admin,o=cloudbot,o=sinobot","ldap4$",'ou=virtualmachineconfig,cn=clc,o=cloudbot,o=sinobot','hostname=default','ou')
#print con
#do_scp_from_remote_host('eucalyptus','ldap4$','192.168.99.147','/var/lib/eucalyptus/.luhya/caches/emi-C8FF107C/machine','/root/pytest/')




		
		
		
