# vim: set ts=2 sw=2 et:

import sys, os, string, logging
import glib
import ldap

import cloudbot
import cloudbot.agent as magent

import apt
from apt import *

def mark_upgrade_deep (cc, pkgname, history = {}):
  depends = set()

  if history.has_key (pkgname):
    return history.get(pkgname)
  else:
    history [pkgname] = None

  history[pkgname] = depends

  try:
    pkg = cc[pkgname]
  except KeyError as e:
    return None

  if len (pkg.versions) == 0:
    return None

  version = max (pkg.versions)
  if version != pkg.installed:
    pkg.mark_upgrade ()
    depends.add (pkgname)

  for deps in version.dependencies:
    for dep in deps.or_dependencies:
      try:
        pkg1 = cc [dep.name]
        if not pkg1.installed:
          continue
      except KeyError as e:
        continue

      l = mark_upgrade_deep (cc, dep.name, history)
      if l is not None:
        depends.update (l)
        history[pkgname] = depends
        break
        
  return depends
  
source_id = None

def ensure_repository():
  logging.info ("verify repository")
  _agent = magent.instance ()
  results = []
  try:
    results =  _agent.Ldap.search_s (_agent.dn, ldap.SCOPE_ONELEVEL,
          filterstr='(objectClass=Repository)', attrsonly=1) 
  except ldap.NO_SUCH_OBJECT as e:
    pass
  except ldap.LDAPError as e:
    return False

  if len (results) > 0:
    return True

  attrlist = [
        ('objectClass', 'Repository'), 
        ('cn', 'repository'),
        ('Lock', '0'),
        ('Revision', '0'),
        ('updateEnable', '0'),
        ('uri', 'deb http://192.168.99.10/ubuntu lucid main extras')
  ]

  try:
    _agent.Ldap.add_s ('cn=repository,%s' % _agent.dn, attrlist)
  except ldap.LDAPError as e:
    logging.fatal ("initialize repository failed %s", e)
    return False
  return True

def ensure_update ():
  _agent = magent.instance ()
  results = []
  try:
    results =  _agent.Ldap.search_s (_agent.dn, ldap.SCOPE_BASE,
          '(objectClass=Agent)', ['curRevision', 'updateRevision']) 
  except ldap.NO_SUCH_OBJECT as e:
    attrlist = [
          (ldap.MOD_REPLACE | ldap.MOD_ADD, 'updateRevision', ['0']),
    ]

    try:
      _agent.Ldap.modify_s (_agent.dn, attrlist)
    except ldap.LDAPError as e:
      logging.error ( "initialize update information failed %s", e)
      return False
    return True

def pre_init (user_data):
  """ pre_init function """
  _agent = magent.instance ()

  if _agent.CAP_REPOSITORY in _agent.capability.values ():
    ensure_repository ()

  ensure_update ()

def post_init (agent):
  source_id = glib.timeout_add_seconds (10, _timeout_routing, agent)

UPDATE_LOCK = 1
UPGRADE_LOCK = 2

def _timeout_routing (agent):
  try:
    _agent = magent.instance ()

    try:
      reposInfo =  _agent.Ldap.search_s (_agent._base, ldap.SCOPE_SUBTREE,
            filterstr='(objectClass=Repository)') 
    except ldap.NO_SUCH_OBJECT as e:
      logging.error ("Repository not found")
      return True 
    except ldap.LDAPError as e:
      logging.error ("LDAP Error %s" % e)
      return True

    if len (reposInfo) == 0:
      logging.error ("Repository not found")
      return True

    data = reposInfo[0][1]

    lock = 0
    if data.has_key ('Lock'): 
      logging.info ("Lock defined %s", data.get('Lock'))
      lock = string.atoi (data.get('Lock')[0])
    else:
      logging.info ("Lock not defined")

    if (lock & UPDATE_LOCK):
      return True

    logging.debug ("check Repository Revision")
    if not data.has_key ('Revision'): 
      return True

    revision = data.get ('Revision')[0]
    logging.debug ("Repository Revision %s" % revision)

    val = _agent.get_attr ('updateRevision')
    if val is None:
      updateRevision = "0"
    else:
      updateRevision = val[0]
    logging.debug ("update Revision %s" % updateRevision)

    val = _agent.get_attr ('curRevision')
    if val is None:
      curRevision = []
    else:
      curRevision = val

    ''' package revison format
      curRevision = desktop-meta:1
      curRevision = nc-meta:1
      curRevision = clc-meta:2
    '''
    revisions = {}

    for l in curRevision:
      pkg, rev = l.split (':')
      revisions [pkg] = rev
    
    logging.debug ("check UPDATE_LOCK")
    if lock & UPGRADE_LOCK:
      return True

    if (updateRevision != revision):
      if not data.has_key('uri'):
        logging.error ( "repository uri not defined" )
        return True

      # update uri file
      try:
        source_list_fn = '/etc/apt/sources.list.d/cloudbot.list'
        fh = open (source_list_fn , 'w')
        
        for uri in data.get('uri'):
          fh.write (uri)
          fh.write ("\n")
        fh.close ()
      except IOError as e:
        logging.error ( "cannot open %s for write %s" % (source_list_fn, e) )
        return True

      retval = os.system ('apt-get update -y -qq')
      if  retval == 0:
        _agent.set_attr ('updateRevision', revision)
      else:
        logging.error ("apt-get update failed:%d" % retval)
        return True

    l = []

    
    for pkg, mask in _agent.capability.items ():
      if revisions.get(pkg) != revision:
        for enable in data.get('updateEnable', []):
          try:
            enable = int (enable)
          except ValueError as e:
            continue
          if enable & mask:
            l.append (pkg) 
          else:
            logging.info ("upgrade disabled: %s" % pkg)
          
    if len (l) == 0:
      return True
    logging.info ("update packages:%s" % l)

    cc = Cache ()
    ag = cc.actiongroup()
    with ag:
      us = set ()
      history = {}
      for pkg in l:
        upgrades = mark_upgrade_deep (cc, pkg, history)
        if upgrades is None:
          logging.error ('failed to get dependency of %s' % pkg)
        else:
          us.update(upgrades)
          revisions[pkg] = revision
      history = None

      if len (us):
        try:
          cc.commit ()
        except apt.cache.LockFailedException as e:
          logging.erro ('apt cache lock failed:%s', e) 
        except Exception as e:
          logging.error ( "unhandled exception:%s" % e)
      else:
        logging.warn ( "no upgrades" )

      try:
        logging.info ( "update package revision in LDAP:%s" % revisions)
        _agent.set_attr ('curRevision', [ "%s:%s" % (pkg, ver) for pkg,ver in revisions.items()])
      except ldap.LDAPError as e:
        logging.error ('failed to update curRevision in LDAP: %s' % e)
    cc = None

  except Exception as e:
    logging.fatal ("unhandled exception:%s" % e)
 
  return True
