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

import sys, ast, commands, logging

# beging----
# blow import code is only for debug
# the sys.path need to be configured after this package is installed.
sys.path.append('../utils')
from cloudbot.utils.sharedClass import *
# end----

class eucaCCNode(AbstractCloudbotNode):

    def __init__(self):
        super(eucaCCNode, self).__init__()
        self._filepath = "%scc_cache" % (NODE_CONFIG_CACHE_PATH)

    def find_myself(self, cc_name):
        attrs = self.getCCCacheInfo()

        myhost = HostMachine()

        ldapsvr = LDAPHandle()

        modifyDN = "ou=clusterconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        if attrs.has_key ('uuid'):
            filter = "(&(uuid=%s)(clusterName=%s))" % (attrs['uuid'], cc_name)
            attrs = ldapsvr.searchEntry(modifyDN, ['clusterName', 'uuid'], filter, ldap.SCOPE_SUBTREE )
            if len (attrs) > 0:
                return attrs 
            else:
                try:
                    os.remove (self._filepath)
                except OSError as e:
                    pass

        hostIP = myhost.getHostIPAddr()
        filter = "(&(hostIPName=%s)(clusterName=%s))" % (hostIP, cc_name)
        attrs = ldapsvr.searchEntry(modifyDN, ['clusterName', 'uuid'], filter, ldap.SCOPE_SUBTREE )

        return attrs

    def getCCCacheInfo(self):
        return HostMachine().getNodeCacheInfo(self._filepath)
    
    def deregister_myself(self):
        attrs = self.getCCCacheInfo()
        cc_name =  attrs['clusterName'][0] 
        self.deregister_myself_with_ccname(cc_name)

    def deregister_myself_with_ccname(self, ccname):
        eucaconf = CloudbotNodeConfig()
        logging.info ('start to Deregister new CC')
        eucaconf.deregister_cc(ccname)
        
    def register_myself(self, cc_name):
        # search if alreay registered
        oldattrs = self.find_myself(cc_name)

        # if exist, store the all attrs to NODE_CONFIG_CACHE_PATH/desktop_cache
        if len(oldattrs) == 0: # not find matched entry
            eucaconf = CloudbotNodeConfig()
            logging.info ('start to register %s' % cc_name)
            eucaconf.register_cc(cc_name)
            oldattrs = self.find_myself(cc_name)
            if len (oldattrs) == 0:
                raise Exception ('register %s failed' % cc_name)  
            else:
                logging.info ("cache cc info locally...")
                fh = open(self._filepath, 'w')
                fh.write(str(oldattrs))
                fh.close()

    def isRunning(self):
        flag = False
        status, output = commands.getstatusoutput('status eucalyptus-cc')
        logging.info (output)
        index = output.find('running')
        if status == 0:
            if index > -1:
                flag = True
        
        return flag

    def start_myself(self):
        logging.info ("Really start cc node... ")
        if not self.isRunning():
            status, output = commands.getstatusoutput('start eucalyptus-cc')
            logging.info (output)
            
    def stop_myself(self):
        logging.info ("Really stop cc node... ")
        if self.isRunning():
            status, output = commands.getstatusoutput('stop eucalyptus-cc')
            logging.info (output)
            
    def heartbeart_timer_handle(self):
        pass

    def restart_timer_handle(self):
        self.stop_myself()
        self.start_myself() 


# test code only
if __name__ == "__main__":
    cc_node = eucaCCNode() 
    cc_node.register_myself('thomas')
    #cc_node.deregister_myself()





