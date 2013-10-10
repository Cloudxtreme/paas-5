__all__ = [ 'eucaCLCWalrusNode', 'eucaCCNode', 'eucaNCNode', 'iFolderNode', 'desktopNode' ]

import sys
import os
import string
import glib
import ldap
import logging

import cloudbot
import cloudbot.agent as magent

from cloudbot.jiedians import *

def register_clc_walrus(user_data):
  try:
    node = eucaCLCWalrusNode.eucaCLCWalrusNode()
    node.register_myself()
  except ldap.LDAPError as e:
    logging.error( "LDAP exception %s" % e)
    return True 
  except Exception as e:
    logging.error( "unhandled exception %s" % e)
    return True 

  return False

def read_config (config_file):
  pairs = {}
  try:
    fh = open (config_file, "r")
    for ln in fh.readlines ():
      ln = ln.strip (' \t\n')
      try:
        key, val = ln.split ('=', 1)
        pairs[key] = val.strip ('" ')
      except ValueError as e:
        continue
  except IOError as e:
    pass

  return pairs

def register_cc (user_data):
  pairs = read_config ("/etc/eucalyptus/eucalyptus-cc.conf")
  cc_name = pairs.get ('CC_NAME')
  if not cc_name:
    return True
  try:
    node = eucaCCNode.eucaCCNode()
    node.register_myself(cc_name)
  except ldap.LDAPError as e:
    logging.error( "LDAP exception %s" % e)
    return True 
  except Exception as e:
    logging.error( "unhandled exception %s" % e)
    return True 

  return False

def register_nc (user_data):
  pairs = read_config ("/etc/eucalyptus/eucalyptus-nc.conf")
  cc_name = pairs.get ('CC_NAME')
  if not cc_name:
    return True
  try:
    node = eucaNCNode.eucaNCNode()
    node.register_myself(cc_name)
  except ldap.LDAPError as e:
    logging.error( "LDAP exception %s" % e)
    return True 
  except Exception as e:
    logging.error( "unhandled exception %s" % e)
    return True 
  return False

def register_storage (user_data):
  try:
    node = iFolderNode.iFolderNode() 
    node.register_myself()
  except ldap.LDAPError as e:
    logging.error( "LDAP exception %s" % e)
    return True 
  except Exception as e:
    logging.error( "unhandled exception %s" % e)
    return True 

  return False

def register_desktop (user_data):
  try:
    node = desktopNode.desktopNode() 
    node.register_myself()
  except ldap.LDAPError as e:
    logging.error( "LDAP exception %s" % e)
    return True 
  except Exception as e:
    logging.error( "unhandled exception %s" % e)
    return True 

  return False

def pre_init (user_data):
  _agent = magent.instance ()

  if _agent.installed (_agent.CAP_CLC):
    if register_clc_walrus (None):
      glib.timeout_add_seconds (5, register_clc_walrus, None)

  if _agent.installed (_agent.CAP_CC):
    if register_cc (None):
      glib.timeout_add_seconds (5, register_cc, None)

  if _agent.installed (_agent.CAP_NC):
    if register_nc (None):
      glib.timeout_add_seconds (5, register_nc, None)

  if _agent.installed (_agent.CAP_STORAGE):
    if register_storage (None):
      glib.timeout_add_seconds (5, register_storage, None)
      
  if _agent.installed (_agent.CAP_DESKTOP):
    if register_desktop (None):
      glib.timeout_add_seconds (5, register_desktop, None)
  return True


def post_init (user_data):
  pass
