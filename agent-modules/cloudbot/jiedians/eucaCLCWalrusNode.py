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

import sys, ldap, commands, logging

# beging----
# blow import code is only for debug
# the sys.path need to be configured after this package is installed.
sys.path.append('../utils')
from cloudbot.utils.sharedClass import *
# end----

class eucaCLCNode(AbstractCloudbotNode):
    def __init__(self):
        super(eucaCLCNode, self).__init__()    
    
    def register_myself(self):
        logging.info ("Really register CLC node... ")
        ldapsvr = LDAPHandle()
        myhost = HostMachine()
        
        hostIP = myhost.getHostIPAddr()
        modifyDN = "cn=clc, o=cloudbot, o=sinobot"
        
        #oldattr = ldapsvr.searchEntry(modifyDN, ['IP', 'hostname', 'cloud-cert-pem'], "objectClass=CLC", ldap.SCOPE_BASE )
        oldattr = ldapsvr.searchEntry(modifyDN, None, "objectClass=CLC", ldap.SCOPE_BASE )
        
        newattr = {}
        newattr['IP']               = [hostIP]
        newattr['hostname']         = [myhost.getHostName()]
        

        has_change = False
        for key, val in oldattr.items ():
            if not newattr.has_key (key):
                newattr[key] = val
            elif newattr.get (key) != val:
                has_change = True
        if has_change or newattr != oldattr:
            ldapsvr.modifyEntry(modifyDN, oldattr, newattr)

    def isRunning(self):
        flag = False
        status, output = commands.getstatusoutput('status eucalyptus-cloud')
        logging.info (output)
        index = output.find('running')
        if status == 0:
            if index > -1:
                flag = True
        
        return flag
        
    def start_myself(self):
        logging.info ("Really start CLC node... ")
        if not self.isRunning():
            status, output = commands.getstatusoutput('start eucalyptus-cloud')
            logging.info (output)
        
    def stop_myself(self):
        logging.info ("Really stop CLC node... ")
        if self.isRunning():
            status, output = commands.getstatusoutput('stop eucalyptus-cloud')
            logging.info (output)

    def heartbeat_timer_handle(self):
        logging.info ("Really heartbeat timer handle for CLC node... ")
        # update heartbeat attr in CLC

    def restart_timer_handle(self):
        pass
            
class eucaWalrusNode(AbstractCloudbotNode):
    def __init__(self):
        logging.info ("Really initialize walrus node... ")
        super(eucaWalrusNode, self).__init__()
        self._filepath = "%swalrus_cache" % (NODE_CONFIG_CACHE_PATH)
    
    def find_myself(self):
        myhost = HostMachine()
        ldapsvr = LDAPHandle()
        
        filter = "hostIPName=*"
        logging.info ("WALRUS filter:", filter)
        
        modifyDN = "ou=walrusconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        
        attrs = ldapsvr.searchEntry(modifyDN, ['hostIPName', 'uuid'], filter, ldap.SCOPE_SUBTREE )
        
        return attrs

    def getWalrusCacheInfo(self):
        return HostMachine().getNodeCacheInfo(self._filepath)
    
    def register_myself(self):
        logging.info ("Really register walrus node... ")
        
        # search if alreay registered
        oldattrs = self.find_myself()
        logging.info ("Wlarus record: ", oldattrs)
        
        hostIP = HostMachine().getHostIPAddr()
        eucaconf = CloudbotNodeConfig()
        need_register = False
        need_deregister = False
        if len(oldattrs) > 0: 
            if oldattrs['hostIPName'][0] != hostIP:
                need_deregister = True
                need_register  = True
        else:
            need_register = True
        
        if need_deregister:
            logging.info ("Deregister walrus first")
            eucaconf.deregister_walrus()
        
        if need_register:    
            logging.info ("Register Walrus later")
            eucaconf.register_walrus()
            oldattrs = self.find_myself()
            if len (oldattrs) == 0:
                raise Exception ("failed to add walrus")

            logging.info ("cache Walrus info locally...")
            fh = open(self._filepath, 'w')
            fh.write(str(oldattrs))
            fh.close()

    def deregister_myself(self):
        logging.info ("Really deregister walrus node... ")
        eucaconf = CloudbotNodeConfig()
        eucaconf.deregister_walrus()       
    
    def isRunning(self):
        flag = False
        status, output = commands.getstatusoutput('status eucalyptus-walrus')
        logging.info (output)
        index = output.find('running')
        if status == 0:
            if index > -1:
                flag = True
        
        return flag

    def start_myself(self):
        logging.info ("Really start walrus node... ")
        if not self.isRunning():
            status, output = commands.getstatusoutput('start eucalyptus-walrus')
            logging.info (output)
        
    def stop_myself(self):
        logging.info ("Really stop walrus node... ")
        if self.isRunning():
            status, output = commands.getstatusoutput('stop eucalyptus-walrus')
            logging.info (output)

    def heartbeat_timer_handle(self):
        logging.info ("Really heartbeat timer handle for walrus node... ")
        # update the heartbeat attr in Walrus
        

    def restart_timer_handle(self):
        pass
        
        
class eucaCLCWalrusNode(object):

    def __init__(self):
        logging.info ("initializing CLC & walrus node ... ...")
        super(eucaCLCWalrusNode, self).__init__()
        self._clcnode = None
        self._walrusnode = None
        
        myhost = HostMachine()
        if myhost.isCLCInstalled() == True:
            self._clcnode = eucaCLCNode()
            
        if myhost.isWalrusInstalled() == True:
            self._walrusnode = eucaWalrusNode()

    def register_myself(self):
        if self._clcnode != None:
            self._clcnode.register_myself()
        if self._walrusnode != None:
            self._walrusnode.register_myself()

    def isRunning(self):
        flag = False
        status, output = commands.getstatusoutput('status eucalyptus')
        logging.info (output)
        index = output.find('running')
        if status == 0:
            if index > -1:
                flag = True
        
        return flag
        
    def start_myself(self):
        if not self.isRunning():
            status, output = commands.getstatusoutput('start eucalyptus')
            logging.info (output)
            
        if self._clcnode != None:
            self._clcnode.start_myself()
            
        if self._walrusnode != None:
            self._walrusnode.start_myself()

    def stop_myself(self):
        if self.isRunning():
            status, output = commands.getstatusoutput('stop eucalyptus')
            logging.info (output)
            
        if self._clcnode != None:
            self._clcnode.stop_myself()

        if self._walrusnode != None:
            self._walrusnode.stop_myself()
        
    def heartbeart_timer_handle(self):
        if self._clcnode != None:
               self._clcnode.heartbeat_timer_handle()
        if self._walrusnode != None:
            self._walrusnode.heartbeat_timer_handle()

    def restart_timer_handle(self):
        status, output = commands.getstatusoutput('restart eucalyptus')
        logging.info (output)
        
        if self._clcnode != None:
            self._clcnode.start_myself()
            
        if self._walrusnode != None:
            self._walrusnode.start_myself()


    # test code only

def test_walrus_node():
    node = eucaWalrusNode()
    node.register_myself()
    #node.deregister_myself()
        
def test_clc_node():
    node = eucaCLCNode() 
    ##    node.stop_myself()
    node.register_myself()
    ##    node.start_myself()
    ##    node.heartbeart_timer_handle()
    ##    node.restart_timer_handle()

def test_clcwalrus_node():
    node = eucaCLCWalrusNode()
    node.register_myself()
    

if __name__ == "__main__":
    test_clcwalrus_node()
    #test_clc_node()
    


