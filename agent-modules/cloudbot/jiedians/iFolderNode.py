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

class iFolderNode(AbstractCloudbotNode):

    def __init__(self):
        super(iFolderNode, self).__init__()
        self._filepath = "%sifolder_cache" % (NODE_CONFIG_CACHE_PATH)

    def find_myself(self):
        myhost = HostMachine()
        ldapsvr = LDAPHandle()
        
        hostIP = myhost.getHostIPAddr()
        filter = "hostIPName=%s" % hostIP
        
        modifyDN = "ou=ifolderconfig, ou=eucaconfig, cn=clc, o=cloudbot, o=sinobot"
        
        attrs = ldapsvr.searchEntry(modifyDN, ['hostIPName', 'uuid'], filter, ldap.SCOPE_SUBTREE )
        return attrs


    def getiFolderCacheInfo(self):
        return HostMachine().getNodeCacheInfo(self._filepath)
    
    def deregister_myself(self):
        eucaconf = CloudbotNodeConfig()
        logging.info ('start to Deregister iFolder')
        status = self.getiFolderCacheInfo()
        _uuid = status['uuid'][0]
        eucaconf.deregister_ifolder(_uuid)
         
    def register_myself(self):
        # search if alreay registered
        oldattrs = self.find_myself()
        
        # if exist, store the all attrs to NODE_CONFIG_CACHE_PATH/desktop_cache
        if len(oldattrs) == 0: # not find matched entry
            eucaconf = CloudbotNodeConfig()
            logging.info ('start to register new ifolder')
            eucaconf.register_ifolder()
            oldattrs = self.find_myself()
        
        logging.info ("cache ifolder info locally...")
        fh = open(self._filepath, 'w')
        fh.write(str(oldattrs))
        fh.close()
            
    def isRunning(self):
        pass

    def start_myself(self):
        pass
            
    def stop_myself(self):
        pass
        
    def heartbeart_timer_handle(self):
        pass

    def restart_timer_handle(self):
        self.stop_myself()
        self.start_myself() 


# test code only
if __name__ == "__main__":
    node = iFolderNode() 
    node.register_myself()
    node.deregister_myself()
    




