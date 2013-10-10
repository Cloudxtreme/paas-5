import sys
import time
import os
import string
import glib
import ldap
import logging

import cloudbot
import cloudbot.agent as magent

import curl, pycurl, zipfile
from euca2ools import Euca2ool, ConnectionFailed
from boto.exception import *

class ClcUtils (object):
  _adminName = "admin"
  _certCode = None
  _accessKey = None
  _secretKey = None
  _url = None

  def __init__ (self):
    pass

  @staticmethod
  def prepareEnv ():
    certCode = ClcUtils.getCertCode ()
    if certCode is None:
      logging.debug ('cannot get certificateCode')
      return False
    else:
      logging.debug ('certificateCode %s', certCode)
    if ClcUtils._certCode and ClcUtils._accessKey and ClcUtils._secretKey:
      return True
    return ClcUtils.fetchZippedCreds ()
    
  @staticmethod
  def fetchZippedCreds ():
    c = curl.Curl ()
    c.set_option(pycurl.SSL_VERIFYPEER, False)
    try:
      c.get ('https://localhost:8443/getX509?user=%s&code=%s' % (ClcUtils._adminName, ClcUtils._certCode))
      ct = c.info ().get ('content-type')
      if not 'application/zip' in ct:
        logging.error ('cannot download credential, html body:%s' % c.body())
        return False
      body = curl.StringIO (c.body())
    except pycurl.error as e:
      logging.error ("cannot download user credentials %s" % e)
      return False
    
    try:
      zfile = zipfile.ZipFile (body)
      eucarc = zfile.read ('eucarc')
      logging.debug ('eucarc %s' % eucarc)
    except TypeError as e:
      logging.error ("bad return" % e)
      return False
    except zipfile.BadZipFile as e:
      logging.error ("bad zip file %s" % e)
      return False

    return ClcUtils.parseEucaRC (eucarc)

  @staticmethod
  def parseEucaRC (rc):
    m = {}
    rc = rc.replace ('export ', '')
    lines = rc.splitlines ()

    logging.debug ('parsing eucarc')
    for line in lines:
      if '=' in line:
        pair = line.split ('=', 1)
        key = pair[0].strip ("\"' ")
        if ' ' in key or '#' in key:
          continue
        val = pair[1].strip ("\"' ")
        m[key] = val
        logging.debug ('\t%s="%s"', key, val)

    try:
      os.environ['EC2_ACCESS_KEY'] = m.get ('EC2_ACCESS_KEY')
      os.environ['EC2_SECRET_KEY'] = m.get ('EC2_SECRET_KEY')
      os.environ['EC2_URL'] = m.get ('EC2_URL')
    except TypeError as e:
      logging.debug ('cannot get keys from eucarc')
      return False

    ClcUtils._accessKey = m.get ('EC2_ACCESS_KEY')
    ClcUtils._secretKey = m.get ('EC2_SECRET_KEY')
    ClcUtils._url = m.get ('EC2_URL')

    return True
     
  @staticmethod
  def getCertCode ():
    if ClcUtils._certCode is None:
      _agent = magent.instance ()
      try:
        ld = _agent.Ldap
        results  = ld.search_s ('cn=%s,%s' % (ClcUtils._adminName, ld.getOption ('CREDENTIAL_DN')), ldap.SCOPE_BASE,
              attrlist=['certificateCode'],
              filterstr='(objectClass=*)'
              ) 
      except ldap.LDAPError as e:
        logging.error ('cannot get certificateCode: %s' % e)
        return None
      if len (results):
        codeAttr = results[0][1].get ('certificateCode')
        if codeAttr:
          ClcUtils._certCode = codeAttr[0]
    return ClcUtils._certCode

  @staticmethod
  def termInstance (instanceID):
    logging.info ('terminate instance %s' % instanceID)
    if not ClcUtils.prepareEnv ():
      return False
    euca = Euca2ool ()
    try:
      euca_conn = euca.make_connection ()
      euca_conn.terminate_instances(instanceID)
    except (ConnectionFailed, exceptions.Exception) as e:
      logging.error (e.message)
      return False

    return True

class DesktopNode (object):
  _nodeCache = {}

  _lastTime = -1
  _gc_interval = 600
  _basedn = 'ou=desktopconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot'

  def __init__ (self, node_data):
    self._timestamp = -1
    self._attr = node_data
  
  @property
  def uuid (self):
    uuids = self._attr.get ('uuid', [])
    if len (uuids) == 0:
      return None
    else:
      return uuids[0]

  @property
  def instanceID (self):
    return self._attr.get ('instanceID')

  @property
  def timestamp (self):
    if self._timestamp == -1:
      self._timestamp = DesktopNode._lastTime
    return self._timestamp
    
  @timestamp.setter
  def timestamp (self, t):
    self._timestamp = t
  
  @property
  def heartbeat (self):
    return self._attr.get ('heartbeat')

  @staticmethod
  def dirtyNodes ():
#[('uuid=bd98dda8-e425-11e0-a30e-34159e23d0c4,ou=nodeconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot', {'objectClass': ['NODECONFIG'], 'IP': ['192.168.99.160'], 'uuid': ['bd98dda8-e425-11e0-a30e-34159e23d0c4'], 'cn': ['192.168.99.160'], 'pcc': ['11111111']})]
    _agent = magent.instance ()
    try:
      results =  _agent.Ldap.search_s (DesktopNode._basedn, ldap.SCOPE_ONELEVEL,
            attrlist=['instanceID', 'heartbeat', 'uuid'],
            filterstr='(&(objectClass=DESKTOPCONFIG)(instanceID=*))'
            ) 
    except ldap.LDAPError as e:
      return None

    nodes = {}
    for node in results:
      # node[0] is uuid, node[1] is map of attr:[val]
      uuids = node[1].get('uuid')
      if uuids and len (uuids) == 1:
        nodes[uuids[0]] = DesktopNode (node[1])
      else:
        logging.error ('invalid DesktopNode %s' % node[1])

    return nodes

  @staticmethod
  def freeNode (key):
    if DesktopNode._nodeCache.has_key (key):
      del DesktopNode._nodeCache[key]
 
  @staticmethod
  def cacheNode (node):
    DesktopNode._nodeCache[node.uuid] = node

  @staticmethod
  def getNode (uuid):
    return DesktopNode._nodeCache.get (uuid)

  @staticmethod
  def listCachedNode ():
    return DesktopNode._nodeCache.keys ()

  def isDead (self, node, t):
    logging.debug ('heartbeat %s:%s, t: %d' % (self.heartbeat, node.heartbeat, t))
    if self.heartbeat == node.heartbeat:
      node.timestamp = self.timestamp 
      if t - node.timestamp > self._gc_interval:
        logging.warn ('node %s is dead', node.uuid)
        return True
      else:
        logging.warn ('maybe node %s is dead', node.uuid)
    else:
      logging.debug ('node %s is alive', node.uuid)
      node.timestamp = t
      self.timestamp = t

    return False

  def freeInstance (self):
    ids = self._attr.get('instanceID')
    if ids is None or len(ids) == 0:
      logging.error ('instanceID attribute not found')
      return;

    instanceID = ids[0]

    if ClcUtils.termInstance (instanceID):
      self.clearInstanceAttr (instanceID)

  def clearInstanceAttr (self, instanceID):
    _agent = magent.instance ()
    try:
      logging.debug('delete instanceID attribute of node')
      _agent.Ldap.modify_s ("uuid=%s,%s" % (self.uuid, DesktopNode._basedn), [(ldap.MOD_DELETE, 'instanceID', None)])
    except ldap.LDAPError as e:
      logging.debug ('cannot clear instanceID %s', instanceID)

def gc_routine (user_data):
  logging.info ('gc routine')
  nodes = DesktopNode.dirtyNodes()

  for key in DesktopNode.listCachedNode():
    if not nodes.has_key (key):
      DesktopNode.freeNode (key)
  if len (nodes) == 0:
    return True
  
  curTime = int (time.time ())

  if DesktopNode._lastTime == -1:
    DesktopNode._lastTime = curTime

  for key, node in nodes.items ():
    old = DesktopNode.getNode (key)
    if old and old.isDead (node, curTime):
      node.freeInstance ()
    else:
      DesktopNode.cacheNode (node)
   
  DesktopNode._lastTime = curTime

  return True 
 
def pre_init (user_data):
  _agent = magent.instance ()

  if _agent.installed (_agent.CAP_CLC):
    glib.timeout_add_seconds (30, gc_routine , None)

