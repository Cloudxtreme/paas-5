# vim: set ts=4 sw=4 et:
# Software License Agreement (BSD License)
#
# Copyright (c) 2011, Sinobot, Inc.
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
# Author: Thomas  thomas.li@sinobot.com.cn

import sys, os,socket,ldap, commands, uuid, ast, base64
import ldap.modlist as modlist
import pwd
import logging


NODE_CONFIG_CACHE_PATH = '/etc/paas/'
LDAP_CONF_FILE = '/etc/eucalyptus/eucalyptus-ldap.conf'

def change_owner (path, owner):
    pw = None
    try:
        pw = pwd.getpwnam (owner)
    except KeyError as e:
        logging.error ('cannot get user info of %s' % owner)
        return False

    try:
        os.chown (path, pw.pw_uid, pw.pw_gid)
    except OSError as e:
        logging.error ('cannot change owner of %s', path)
        return False
    return True


class AbstractCloudbotNode(object):

    def __init__(self):
        if not os.path.exists(NODE_CONFIG_CACHE_PATH):
            print "create %s" % NODE_CONFIG_CACHE_PATH
            os.makedirs(NODE_CONFIG_CACHE_PATH)

    def register_myself(self):
        pass

    def isRunning(self):
        pass
        
    def start_myself(self):
        pass

    def stop_myself(self):
        pass

    def heartbeat_timer_handle(self):
        pass

    def restart_timer_handle(self):
        pass


class LDAPHandle(object):

    def __init__(self):
        self._ldap_opts={}
        self.initFromConf()
    
    def set_username(self, username):
        self._ldap_opts['LDAP_USER'] = username
 
    def get_username(self):
        return self._ldap_opts['LDAP_USER']
    
    def set_password(self, password):
        self._ldap_opts['LDAP_PASSWORD'] = password

    def get_password(self):
        return self._ldap_opts['LDAP_PASSWORD'] 
        
    def set_ldap_addr(self, ipaddr):
        self._ldap_opts['LDAP_SERVER'] = ipaddr
        
    def get_ldap_addr(self):
        return self._ldap_opts['LDAP_SERVER']
    
    def initFromConf(self, filepath = LDAP_CONF_FILE):
        fh = None
        try:
            fh = open (filepath);
            for l in fh.readlines ():
                if '=' in l:
                    key, val = l.split ('=', 1)
                    self._ldap_opts[key] = val.strip("\n").strip('"')
        except IOError as e:
            return False
        finally:
            if fh:
                fh.close ()
            return True
    
    def ldapInit(self):
        ldapip = self.get_ldap_addr()
        try:
            l = ldap.open(ldapip)
            l.protocol_version = ldap.VERSION3

            username = self.get_username()
            password  = self.get_password()

            l.simple_bind(username, password)
        except  ldap.LDAPError, e:
            print e
            return None
        return l
    
    # The dn of our new entry/object
    # dn="cn=replica,dc=example,dc=com" 
    # A dict to help build the "body" of the object
    #    attrs = {}
    #    attrs['objectclass'] = ['top','organizationalRole','simpleSecurityObject']
    #    attrs['cn'] = 'replica'
    #    attrs['userPassword'] = 'aDifferentSecret'
    #    attrs['description'] = 'User object for replication using slurpd'
    
    def addEntry(self, newDN, attrs):
        l = self.ldapInit()
                    
        ldif = modlist.addModlist(attrs)
        l.add_s(newDN, ldif)
        l.unbind_s()
        
    def searchEntry(self, baseDN, attrIDList, Filters, scope):
        l = self.ldapInit()
        
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
                    attrIDList =  result_set[0][0][1].keys()                  

                for attr in attrIDList:
                    retvalue[attr] = result_set[0][0][1].get (attr)
                
        except ldap.LDAPError, e:
            print "--- ldap search error"
            retvalue = {}
        
        #print  'last result:', retvalue
        return retvalue
    
    def modifyEntry(self, modifyDN, oldattrs, newattrs, ignore_attr_types=None, ignore_oldexistent=0):
        l = self.ldapInit()
        
        ldif = modlist.modifyModlist(oldattrs, newattrs, ignore_attr_types, ignore_oldexistent)
        l.modify_s(modifyDN, ldif)
        
        l.unbind_s ()
    
    def deleteEntry(self, delDN):
        l = self.ldapInit()
        
        try:
            l.delete_s(delDN)
        except ldap.LDAPError, e:
            print e
        
class HostMachine(object):
    
    def __init__(self):
        pass
    
    def getNodeCacheInfo(self, _filepath):
        attrs = {}
        try:
          fh = open(_filepath,'r')
          output = fh.read()
          fh.close ()
          attrs = ast.literal_eval(output)
        except IOError as e:
          pass
        
        return attrs
    
    def getHostName(self):
        ret = None
        status, output = commands.getstatusoutput('hostname')
        if status == 0:
            ret = output
        
        return ret
        
    def getHostIPAddr(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('www.zjut.edu.cn',80))
        
        return s.getsockname()[0]
    
    def getMachineID(self):
        fh = None
        try:
            fh = open ('/var/lib/dbus/machine-id')
            machineid = fh.readline()
            machineid = machineid.strip("\n")
        except IOError as e:
            print e
        finally:
            if fh:
                fh.close ()
                
        return machineid
    
    def isCLCInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep eucalyptus-cloud')
        if status == 0 :
            flag = True
        else:
            flag = False
            
        return flag
        
    def isWalrusInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep eucalyptus-walrus')
        if status == 0 :
            flag = True
        else:
            flag = False
        
        return flag
        
    def isCCInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep eucalyptus-cc')
        if status == 0 :
            flag = True
        else:
            flag = False
        
        return flag
    
    def isNCInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep eucalyptus-nc')
        if status == 0 :
            flag = True
        else:
            flag = False
        
        return flag        
        
    def isIFolderInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep cloudbot-ifoler')
        if status == 0 :
            flag = True
        else:
            flag = False
        
        return flag
    
    def isDesktopInstalled(self):
        status, output = commands.getstatusoutput('dpkg -l | grep cloudbot-desktop')
        if status == 0 :
            flag = True
        else:
            flag = False
        
        return flag
    
class CloudbotNodeConfig(object):
    
    def __init__(self):
        self.clcip = self.getCLCIP()
    
    # some utility functions
    def genUUID(self):
        return uuid.uuid1()
        
    def getDateString(self):
        cmdline = "date -u +%Y-%m-%dT%H%%3A%M%%3A%S.000Z"
        status, output = commands.getstatusoutput(cmdline)
        return output
        
    def getAdminSecretKey(self):
        ldapsvr = LDAPHandle()
        password = ldapsvr.get_password()
        cmdline = "ldapsearch -h %s -p 389 -D cn=admin,o=cloudbot,o=sinobot -w %s -b ou=auth_info,ou=auth_user,o=cloudbot,o=sinobot -s sub 'UserNAME=admin*' attributes secretKey -LLL | grep secretKey" % (self.clcip, password)
        status, output = commands.getstatusoutput(cmdline)
        if status != 0:
            return None
        return output.split(':')[1].strip()
        
    def getAdminAccessKey(self):
        ldapsvr = LDAPHandle()
        password = ldapsvr.get_password()
        cmdline = "ldapsearch -h %s -p 389 -D cn=admin,o=cloudbot,o=sinobot -w %s -b ou=auth_info,ou=auth_user,o=cloudbot,o=sinobot -s sub 'UserNAME=admin*' attributes queryId -LLL | grep queryId" % (self.clcip, password)
        status, output = commands.getstatusoutput(cmdline)
        if status != 0:
            return None
        return output.split(':')[1].strip()

    def getCLCIP(self):
        ldapsvr = LDAPHandle()
        modifyDN = "cn=clc, o=cloudbot, o=sinobot"
        attrs = ldapsvr.searchEntry(modifyDN, ['IP'], 'IP=*', ldap.SCOPE_BASE )
        return attrs['IP'][0] 
    
    # walrus related functioins
    def deregister_walrus(self):
        # createCloudURL "Action" "DeregisterWalrus" "Name" "walrus";
        argslist = "AWSAccessKeyId=%s&Action=DeregisterWalrus&Name=walrus&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s&Version=eucalyptus" % (self.getAdminAccessKey(), self.getDateString())
        url = self.createCloudURL(argslist)
        self.check_ws(url)
        
    def register_walrus(self):
        # createCloudURL "Action" "RegisterWalrus" "Host" "${WALRUS}" "Name" "walrus" "Port" "8773
        hostIP = HostMachine().getHostIPAddr()
        argslist = "AWSAccessKeyId=%s&Action=RegisterWalrus&Host=%s&Name=walrus&Port=8773&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s&Version=eucalyptus" % (self.getAdminAccessKey(), hostIP, self.getDateString())
        url = self.createCloudURL(argslist)
        retstr = self.check_ws(url)
        if len(retstr) == 0:
            if self.checkHeartbeat('walrus') == True:
                ph = GetCertPK()
                #ph.get_euca_p12()
    
    def checkCLCService (self):
        self.check_ws ('https://%s:8443/register' % self.clcip, '--no-check-certificate')
        
    # CC related functions
    def register_cc(self, cc_name):
        # createCloudURL "Action" "RegisterCluster" "Host" "${NEWCLUS}" "Name" "${CLUSNAME}" "Port" "${CC_PORT}"
        hostIP = HostMachine().getHostIPAddr()
        argslist = "AWSAccessKeyId=%s&Action=RegisterCluster&Host=%s&Name=%s&Port=8774&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s&Version=eucalyptus" % (self.getAdminAccessKey(), hostIP, cc_name, self.getDateString())
        url = self.createCloudURL(argslist)
        self.check_ws(url)

        #sync keys
        ph = GetCertPK()
        ph.get_cloud_cert_pem()
        ph.get_vtunpass(cc_name)
        ph.get_cluster_pk_pem(cc_name)
        ph.get_cluster_cert_pem(cc_name)
        ph.get_node_pk_pem(cc_name)
        ph.get_node_cert_pem(cc_name)
    
    def deregister_cc(self, cc_name):
        # createCloudURL "Action" "DeregisterCluster" "Name" "${CLUSNAME}"
        argslist = "AWSAccessKeyId=%s&Action=DeregisterCluster&Name=%s&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=%s&Version=eucalyptus" % (self.getAdminAccessKey(), cc_name, self.getDateString())
        url = self.createCloudURL(argslist)
        self.check_ws(url)
    
    
    # NC related functions
    def register_nc(self, cc_name):
        _uuid = str(self.genUUID())
        dn = "uuid=%s, ou=nodeconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        hostIP = HostMachine().getHostIPAddr()
        attrs = {}
        attrs['cn'] = hostIP
        attrs['uuid'] = _uuid
        attrs['IP'] = hostIP
        attrs['pcc'] = cc_name
        attrs['objectclass'] = ['NODECONFIG']
        
        ldapsvr = LDAPHandle()
        ldapsvr.addEntry(dn, attrs)

        # sync keys
        ph = GetCertPK()
        ph.get_cloud_cert_pem()
        ph.get_node_pk_pem(cc_name)
        ph.get_node_cert_pem(cc_name)
        ph.get_cluster_cert_pem(cc_name)
        
    def deregister_nc(self, _uuid):
        dn = "uuid=%s, ou=nodeconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        ldapsvr = LDAPHandle()
        print dn
        ldapsvr.deleteEntry(dn)
        
    # iFolder related functions
    def register_ifolder(self):
        _uuid = str(self.genUUID())
        dn = "uuid=%s, ou=ifolderconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        hostIP = HostMachine().getHostIPAddr()
        attrs = {}
        attrs['uuid'] = _uuid
        attrs['hostIPName'] = hostIP
        attrs['objectclass'] = ['IFOLDERCONFIG']
        
        ldapsvr = LDAPHandle()
        print dn
        print attrs
        ldapsvr.addEntry(dn, attrs)
    
    def deregister_ifolder(self, _uuid):
        dn = "uuid=%s, ou=ifolderconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        ldapsvr = LDAPHandle()
        print dn
        ldapsvr.deleteEntry(dn)
        
    # Desktop related functions
    def register_desktop(self):
        _uuid = str(self.genUUID())
        dn = "uuid=%s, ou=desktopconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        hostIP = HostMachine().getHostIPAddr()
        attrs = {}
        attrs['uuid'] = _uuid
        attrs['hostIPName'] = hostIP
        attrs['objectclass'] = ['DESKTOPCONFIG']
        
        ldapsvr = LDAPHandle()
        print dn
        print attrs
        ldapsvr.addEntry(dn, attrs)
                
    def deregister_desktop(self, _uuid):
        dn = "uuid=%s, ou=desktopconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot" % ( _uuid )
        ldapsvr = LDAPHandle()
        print dn
        ldapsvr.deleteEntry(dn)
        
    
    # basic functions for access eucalyptus web service
    def createCloudURL(self, argslist):
        
        secreateKey = self.getAdminSecretKey()
        
        httpHeader = "GET\n%s\n/services/Configuration\n"  % (self.clcip)
        httpURL = "http://%s:8773/services/Configuration?" % (self.clcip)

        httpHeader = "%s%s" % (httpHeader, argslist)
        
        tmpfile = '/tmp/likaifeng'
        fileHandle = open ( tmpfile, 'w' )
        fileHandle.write ( httpHeader )
        fileHandle.close()
        
        cmdline = "openssl dgst -sha256 -hmac %s -binary %s | openssl base64" % (secreateKey, tmpfile)
        status, output = commands.getstatusoutput(cmdline)
        
        arg_signature = "Signature=%s" % (output)  
        httpURL = "%s%s&%s" % (httpURL, argslist, arg_signature)
        
        return httpURL
        
    def check_ws(self, _url, opt=''):
        cmdline = "/usr/bin/wget -q -T 10 -t 1 -O - %s '%s'" % (opt, _url)
        status, output = commands.getstatusoutput(cmdline)
        #print  "wget output: ", output
        cmdline = "echo '%s' | grep faultstring | sed 's:.*<faultstring>\(.*\)</faultstring>.*:\1:'" % (output)
        status, output1 = commands.getstatusoutput(cmdline)
        if len(output) > 0:  # get report from CLC
            return output1
        else:                # big error appears
            return 'fatal error occures, pls check the CLC Log'
    
    def checkHeartbeat(self, _type_v):
        cmdline = "/usr/bin/wget -q -T 10 -t 1 -O - http://%s:8773/services/Heartbeat | grep %s" % (self.clcip, _type_v)
        status, output = commands.getstatusoutput(cmdline)
        myarray = output.split()
        print myarray
        isEnable = myarray[1].split("=")[1]
        isLocal  = myarray[2].split("=")[1]
        if isEnable == 'true' and isLocal == 'true':
            return True
        else:
            return False
    
class GetCertPK(object):
    def __init__(self):
        self.ldaph = LDAPHandle()
        
    # download euca.p12 when walrus is registerd
    def get_euca_p12(self):
        # get base64 formated euca.p12
        modifyDN = "cn=clc, o=cloudbot, o=sinobot"
        attrs = self.ldaph.searchEntry(modifyDN, ['euca-p12'], "IP=*", ldap.SCOPE_BASE )
        
        # need base64 transform and save to /var/lib/eucalyptus/keys/euca.p12
        eucap12base64Str = attrs['euca-p12'][0]
        bin_eucap12 = base64.decodestring(eucap12base64Str)
        fh = open ('/var/lib/eucalyptus/keys/euca.p12', 'w')
        fh.write(bin_eucap12)
        fh.close()

    def get_cluster_cert_pem(self, cc_name):
        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        filter = "clusterName=%s" % cc_name
        attrs = self.ldaph.searchEntry(modifyDN, ['cluster-cert-pem'], filter, ldap.SCOPE_SUBTREE )
        
        fh = open ('/var/lib/eucalyptus/keys/cluster-cert.pem', 'w')
        fh.write(attrs['cluster-cert-pem'][0])
        fh.close()        

    def get_cluster_pk_pem(self, cc_name):
        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        filter = "clusterName=%s" % cc_name
        attrs = self.ldaph.searchEntry(modifyDN, ['cluster-pk-pem'], filter, ldap.SCOPE_SUBTREE )
        
        fh = open ('/var/lib/eucalyptus/keys/cluster-pk.pem', 'w')
        fh.write(attrs['cluster-pk-pem'][0])
        fh.close()
        
    def get_node_cert_pem(self, cc_name):
        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        filter = "clusterName=%s" % cc_name
        attrs = self.ldaph.searchEntry(modifyDN, ['node-cert-pem'], filter, ldap.SCOPE_SUBTREE )
        
        fh = open ('/var/lib/eucalyptus/keys/node-cert.pem', 'w')
        fh.write(attrs['node-cert-pem'][0])
        fh.close()
        
    def get_node_pk_pem(self, cc_name):
        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        filter = "clusterName=%s" % cc_name
        attrs = self.ldaph.searchEntry(modifyDN, ['node-pk-pem'], filter, ldap.SCOPE_SUBTREE )
        
        fh = open ('/var/lib/eucalyptus/keys/node-pk.pem', 'w')
        fh.write(attrs['node-pk-pem'][0])
        fh.close()
    
    def get_vtunpass(self, cc_name):
        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        filter = "clusterName=%s" % cc_name
        attrs = self.ldaph.searchEntry(modifyDN, ['vtunpass'], filter, ldap.SCOPE_SUBTREE )
        
        fh = open ('/var/lib/eucalyptus/keys/vtunpass', 'w')
        fh.write(attrs['vtunpass'][0])
        fh.close()
    
    def get_cloud_cert_pem(self):
        modifyDN = "cn=clc, o=cloudbot, o=sinobot"
        filter = "IP=*"
        attrs = self.ldaph.searchEntry(modifyDN, ['cloud-cert-pem'], filter, ldap.SCOPE_BASE )
        
        fh = open ('/var/lib/eucalyptus/keys/cloud-cert.pem', 'w')
        fh.write(attrs['cloud-cert-pem'][0])
        fh.close()
    

# 1. test ldaphandle
def test_ldapHandle():
    ldapsvr = LDAPHandle()
    ldapsvr.set_username('cn=admin,o=cloudbot,o=sinobot')
    ldapsvr.set_password('ldap4$')
    ldapsvr.set_ldap_addr('localhost')
    
    print ldapsvr.get_username()
    print ldapsvr.get_password()
    
    host = HostMachine()
    mID = host.getMachineID()
    print mID
    baseDN = "ou=deploy, o=cloudbot,o=sinobot"
    newDN = "cn=%s,%s" % (mID, baseDN)
    print newDN
    attrs={}
    #attrs['objectclass'] = ['top','organizationalUnit']
    attrs['objectclass'] = ['MACHINE']
    attrs['machineID'] = mID  #'d7a81350299aef7acd14633d4e1518cd'

    print attrs['machineID']
    ldapsvr.addEntry(newDN, attrs)
    
    
# 2. test HostMachine
def test_hostmachine():
    myhost = HostMachine()
    print myhost.isCLCInstalled()   
    print myhost.isWalrusInstalled() 

def test_walrus_register():
    myconfig = CloudbotNodeConfig()
    myconfig.register_walrus()
    #myconfig.deregister_walrus()
    #myconfig.checkHeartbeat('walrus')
    #print myconfig.getAdminSecretKey()
    #print myconfig.getAdminAccessKey()

def test_cc_register():
    myconfig = CloudbotNodeConfig()
    #myconfig.register_cc('likaifeng')
    myconfig.deregister_cc('liyinghong')

def test_nc_register():
    myconfig = CloudbotNodeConfig()
    #myconfig.register_nc('likaifeng')
    myconfig.deregister_desktop('f986f7d2-c3f0-11e0-9165-f04da2a03854')

def test_cert_pk_fun():
    ph = GetCertPK()
    ph.get_euca_p12()
    ph.get_vtunpass('thomas')
    ph.get_cloud_cert_pem()
    ph.get_cluster_pk_pem('thomas')
    ph.get_node_pk_pem('thomas')
    #ph.get_node_cert_pem('thomas')
    #ph.get_cluster_cert_pem('thomas')
    
if __name__ == "__main__":
    eucaconfig = CloudbotNodeConfig()
    eucaconfig.deregister_cc('thomas')
    eucaconfig.register_cc("likaifeng")
    


