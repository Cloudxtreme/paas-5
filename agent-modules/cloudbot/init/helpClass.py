import sys, os, logging, string
import time
import ldap, glob

class CloudLDAP(ldap.ldapobject.LDAPObject):
    """
    Helper c lass to access LDAP
    """
    LDAP_OPTION_MAPPING = {
        'DEPLOY_DN' : 'ou=deploy,o=cloudbot,o=sinobot'
    }

    def __init__ (self, uri = None, bdn = 'o=cloudbot,o=sinobot'):
        self._read_config ()
        if uri:
            self.LDAP_OPTION_MAPPING['LDAP_URI'] = uri
        self.LDAP_OPTION_MAPPING['DEPLOY_DN'] = "ou=deploy,%s" % bdn
        ldap.ldapobject.LDAPObject.__init__ (self, self.LDAP_OPTION_MAPPING['LDAP_URI'])
        self.set_option (ldap.OPT_PROTOCOL_VERSION, 3)
        self.bind_s()

    def bind_s (self, who=None, cred=None, method=128):
        if who:
            self.LDAP_OPTION_MAPPING['LDAP_USER'] = who
        if cred:
            self.LDAP_OPTION_MAPPING['LDAP_PASSWORD'] = cred

        ldap.ldapobject.LDAPObject.bind_s (self, self.LDAP_OPTION_MAPPING['LDAP_USER'], self.LDAP_OPTION_MAPPING['LDAP_PASSWORD'], method)

    def _read_config (self, config_fn = "/etc/eucalyptus/eucalyptus-ldap.conf"):
        try:
            fh = open (config_fn, 'r')
            for l in fh.readlines ():
                if '=' in l:
                    key, val = l.split ('=', 1)
                    val = val.strip(' "\n')
                    self.LDAP_OPTION_MAPPING[key] =  val
            fh.close () 
        except IOError as e:
            print (sys.stderr, "cannot open %s: %s\n", config_fn, e)

        return True
  
    def getOption (self, opt):
        return self.LDAP_OPTION_MAPPING.get (opt)

class Agent(object):
    """
    An class holds information of current machine. 
    """
    _machine_id = None
    _base = 'ou=deploy,o=cloudbot,o=sinobot'
    _ethernet = {}

    _ldap = None

    CAP_CLC =  1
    CAP_WALRUS =  2
    CAP_CC = 4
    CAP_NC = 8
    CAP_DESKTOP = 16
    CAP_STORAGE = 32
    CAP_REPOSITORY = 64

    _capability_def  = {
        'clc-meta' : CAP_CLC,
        'walrus-meta' : CAP_WALRUS,
        'cc-meta' : CAP_CC,
        'nc-meta' : CAP_NC,
        'desktop-meta' : CAP_DESKTOP,
        'storage-meta': CAP_STORAGE,
        'repository-meta': CAP_REPOSITORY
    }

    _capability = None
    
    __instance = None
    
    # sigleton member-function to return the instance of Agent
    @staticmethod 
    def getInstance(): 
        if __instance == None:
            __instance = Agent()
        return __instance

    def __init__ (self):
        pass

    @property
    def capability (self):
	    
		if self._capability is None:

		  installed_packages = {}
		  self._capability = {}
		  fh = os.popen ('dpkg -l')
		  for line in fh.readlines ():
			fields = line.split ()
			if len (fields) >= 3:
			  if fields[0] in ['ii', 'iU']:
				installed_packages [fields[1]] = fields[2]
		  fh.close ()

		  for key, bit in self._capability_def.items ():
			if installed_packages.has_key (key):
			  logging.info ( "%s installed %d" % (key, bit))
			  self._capability [key] = bit
		return self._capability

    def installed (self, cap):
        return (cap in self.capability.values ())

    @property
    def base(self):
        return self._base 

    @property
    def dn (self):
        return 'cn=%s,%s' % (self.Id, self._base)

    @property
    def Ldap(self):
        return CloudLDAP ()

    @property
    def Id(self):
		if self._machine_id is None:
		  fh = None
		  try:
			fh = open ('/var/lib/dbus/machine-id')
			self._machine_id = fh.readline ()
			self._machine_id = self._machine_id.strip (' \n\r') 
			fh.close ()
		  except IOError as e:
			raise
		return self._machine_id

    @property
    def ethernet(self):
        return self._ethernet

    @ethernet.setter
    def ethernet(self, ethernet):
        self._ethernet = ethernet 
  
    def ensure_machine (self):
		results = []
		try:
		  results =  self.Ldap.search_s (self.base, ldap.SCOPE_ONELEVEL,
				filterstr='(&(objectClass=Agent)(cn=%s))' % self.Id, attrsonly=1) 
		  if len (results) > 0: 
			return True
		except ldap.NO_SUCH_OBJECT as e:
		  logging.info ("not found machine")
		except ldap.LDAPError as e:
		  logging.info ("search LDAP failed %s", e)
		  return False

		attrlist = [
			  ('objectClass', ['Agent']), 
			  ('cn', self.Id)
		]

		try:
		  logging.info ("add machine cn=%s,%s" % (self.Id, self.base))
		  self.Ldap.add_s ('cn=%s,%s' % (self.Id, self.base), attrlist)
		except ldap.LDAPError as e:
		  logging.error ("add %s LDAP failed %s", attrlist, e)
		  return False
		return True

    def get_attr (self, attr):
		results =  self.Ldap.search_s (self.dn, ldap.SCOPE_BASE)
		if results is None or len (results) == 0:
		  return None

		for key, data in results[0][1].items():
		  if key == attr:
			return data
		return None
   
    def set_attr (self, attr, data, op = ldap.MOD_ADD | ldap.MOD_REPLACE):
        self.Ldap.modify_s (self.dn, [(op, attr, data)])

    def iface_get_config (self, dev):
		  configs = {}
		  fh = os.popen ('/sbin/ifconfig %s' % dev)
		  
		  for ln in fh.readlines ():
			if 'inet addr:' in ln:
			  ln = ln.replace ('inet addr', 'addr')
			  ln = ln.strip (' \n')
			  for pair in ln.split ():
				key, val = pair.split (':')
				configs[key] = val
			  break
			  
		  return (configs.get('addr'), configs.get('Mask'))

    def ethernet_monitor(self):
		  if not self.ensure_machine():
			return True

		  ethernet = {}
		  for dev in glob.glob ('/sys/class/net/eth?'):
			dev = dev.replace ('/sys/class/net/','')
			ipaddr, netmask = self.iface_get_config (dev)
			if ipaddr is None:
			  ipaddr = ''
			ethernet [dev] = ipaddr

		  for dev, ipaddr in ethernet.items():
			if ethernet.get(dev, '') != ipaddr:
			  # ip address changed, update
			  ethernet [dev] = ethernet[dev]
			else:
			  # remove item that is not changed
			  del ethernet[dev]

		  # add items not in agent
		  for dev, ipaddr in ethernet.items ():
			ethernet [dev] = ipaddr 

		  if len (ethernet) > 0:
			logging.info ("ethernet change detected %s" % ethernet)
			# there are changes
			try:
			  attrlist = [
					(ldap.MOD_REPLACE, 'eth', [ '%s:%s' % (dev,ip) for dev,ip in ethernet.items ()]),
			  ]
			  logging.info ("add %s %s" % (dn, attrlist))
			  self.Ldap.modify_s (dn, attrlist)
			except ldap.LDAPError as e:
			  logging.error ("update ethernet config failed %s", e)
		  return True
		  
def preInit (user_data):
    """ pre_init function """
    magent = Agent()
  
    # check ip address, and store in LDAP
    while not magent.ensure_machine():
        logging.error ("cannot initialize agent")
        time.sleep (5)
    magent.ethernet_monitor()

def postInit (user_data):
    pass		  
