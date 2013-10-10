#!/usr/bin/python -u 

__version__ = '1.0.0'

import sys
import os
import logging
import logging.handlers
import time
import datetime

MAX_LOGFILE_BYTE=10*1024*1024
LOG_FILE='/var/log/eucalyptus/cloud-agent.log'
MAX_LOG_COUNT=10
    
def init_log():
  logger = logging.getLogger('')
  ch = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOGFILE_BYTE,backupCount=MAX_LOG_COUNT)
  formatter = logging.Formatter('<%(asctime)s> <%(levelname)s> <%(module)s:%(lineno)d>\t%(message)s' , datefmt='%F %T')
  ch.setFormatter(formatter)
  logger.addHandler(ch)
  logger.setLevel(logging.ERROR)
  return logger


logger = init_log()

def loadModule (modname): 
  mod = None
  logger.info ("loading module %s", modname)
  try:
    mod = __import__ (modname)
  except ImportError as e:
    logger.error ("import %s failed:%s\n" % (modname, e))
    return None
  return mod

# load all modules
# return: 0 OK, -1 error occur
def loadModules (user_data):
    '''
      each module should register itself in '/etc/cloud-agent/modules'
      01_update 05_euca
    '''
    path = '/etc/cloud-agent/modules'
    modules = os.listdir(path)
    modules.sort ()
    for modname in modules:
        if '_' in modname:
          modname = "cloudbot." + modname.split ('_')[1]
          if loadModule (modname):
            m = sys.modules[modname]
            if m and getattr(m, 'preInit', False):
              try:
                m.preInit (user_data)      # agent holds global config and ldap handler
              except Exception as e:
                logger.error ("preInit module %s failed: %s" % (m, e))
                continue
          else:
			  logger.error ("load module %s faileds" % modname)
			  continue
			  			  
    for modname in modules:
        if '_' in modname:
          modname = "cloudbot." + modname.split ('_')[1]
          m = sys.modules.get(modname)
          if m and getattr(m, 'postInit', False):
            try:
              m.postInit (user_data)
            except Exception as e:
              logger.error ("postInit module %s failed: %s" % (m, e))
              continue
    return 0
        
def main ():
  os.putenv ('LANG', 'en_US')
   
  rev = loadModules (None)
  if rev == -1:
      logger.error('Cloud-agent loading modules error! Please ckeck!')
	  
  while True:
  	  time.sleep(100000)


if __name__ == '__main__':
  main ()
