##################################################
# openldap used
##################################################
MAX_LOGFILE_BYTE=10*1024*1024
LOG_FILE_ERROR='/var/log/eucalyptus/cloud-agent-error.log'
LOG_FILE_WARN='/var/log/eucalyptus/cloud-agent-warn.log'
LOG_FILE_INFO='/var/log/eucalyptus/cloud-agent-info.log'
LOG_FILE_DEBUG='/var/log/eucalyptus/cloud-agent-debug.log'
MAX_LOG_COUNT=10

DEFAULT_DELAY = 2
LDAP_CONF_FILE = '/etc/eucalyptus/eucalyptus-ldap.conf'
REAL_LDAP_CONF_FILE = '/etc/eucalyptus/eucalyptus-real-ldap.conf'

#######################################################
#proxy clc used
#######################################################
USER_ROOT = '/var/lib/eucalyptus/.luhya/users/'
IMAGE_CACHE_ROOT = '/var/lib/eucalyptus/.luhya/caches/'
USER_LOGON_FILE = 'logon.xml'
CLIENT_INFO_FILE = 'clientdata.xml'
IMAGE_INFO_FILE = 'imageinfo.xml'
USER_IMAGES_INFO_FILE = 'imageinfos.xml'

##############################################
# proxy ldap used
##############################################
NODE_INFO_FILE='/var/lib/eucalyptus/.luhya/ldapcaches/local_node.xml'
CLUSTER_INFO_FILE='/var/lib/eucalyptus/.luhya/ldapcaches/cluster.xml'
CLC_INFO_FILE='/var/lib/eucalyptus/.luhya/ldapcaches/clc.xml'
CATEGORIES_INFO_FILE = '/var/lib/eucalyptus/.luhya/ldapcaches/categories.xml'
WALRUS_INFO_FILE = '/var/lib/eucalyptus/.luhya/ldapcaches/walrus.xml'
LDAP_CACHE_ROOT = '/var/lib/eucalyptus/.luhya/ldapcaches/'

ONLINE_CONNECT_INTV = 5
OFFLINE_CONNECT_INTV= 5
VM_CPU_UTILIZATION = 75

THRIFT_TIMEOUT = 3000

#########################
#  clc used
#########################
SERVER_SOURCE_INTV = 10
INS_INIT = 'initialization'
INS_DOWNLOADING = 'downloading'
INS_DOWNLOADFAILED = 'download-failed'
INS_PENDING = 'pending'
INS_RUNNING = 'running'
INS_RUNFAILED = 'run-failed'
INS_SHUTDOWN = 'shutting-down'
INS_TERMINATED = 'terminated'
BACKUP_INTERVAL = 5
CLOUD_CLC = 'eucalyptus-cloud'

############################
# cc used
############################
CLOUD_CC = 'eucalyptus-cc'
DEFAULT_EUCA_HOME = '/var/lib/eucalyptus'
INSTANCE_REPORT_INTV = 1
HEART_BEAT_INTV = 1
CC_CONF_FILE = '/etc/eucalyptus/eucalyptus-cc.conf'

###############################
#walrus used
###############################
CLOUD_WALRUS = 'eucalyptus-walrus'
IMAGE_DEFAULT_PATH = '/storage/images/'
IMAGE_FILE_NAME = 'machine'

###############################
# nc used
###############################
IMAGE_BASE_DN = 'ou=images,cn=clc,o=cloudbot,o=sinobot'
IMAGE_SEARCH_FILTER_ROOT = 'imageId='
IMAGE_IMAGE_KEY = 'imageLocation'
DEFAULT_IMAGE_STYLE = 'm1.small'
WALRUS_BASE_DN = 'ou=walrusconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot'
WALRUS_SEARCH_FILTER = 'walrusName=walrus'
WALRUS_HOST_KEY = 'hostIPName'
WALRUS_PORT_KEY = 'port'
ISO_FILE_PATH = '/var/lib/eucalyptus/storage/iso/'
P2V_FILE_PATH = '/var/lib/eucalyptus/storage/p2v/'
DEFAULT_IMAGE_NAME = 'machine'
ISO_PAIH_PREFIX = 'iso'
P2V_PATH_PREFIX = 'p2v'
ISO_EXTERN_NAME = 'iso'
BACKUP_ROOT_PATH = '/var/lib/eucalyptus/backup/'
IMAGE_PREFIX = 'emi-'
EXT_DISK_NODE = '/var/lib/eucalyptus/extdisk/'
EXT_DISK_WALRUS = '/storage/images/extdisk/'
EXT_DISK_FILE = 'disk2'
MAXTIMES = 100
START_PORT = 5900
MAX_PORT = 6100
MILLION_BYTE = 1024 * 1024      # MB
RESERVE_DISK = 500                  # walrus reserve disk : MB
#result definition
RET_OK = 0
RET_ERROR = -1
RET_RUN_FAILED = -2
RET_NO_RESOURCE = -3
RET_CREATE_FAILED = -4
VM_MEMERY = 1048576                     #vm memery 1GB
VM_CPUS = 1                                     #vcpus
MAXUPLOADTIMES = 50                     # max to indentify whether upload thread is working 
BUFF_LEN = 1024*1024
NC_CONF_FILE = '/etc/eucalyptus/eucalyptus-nc.conf'
CLOUD_NC = 'eucalyptus-nc'

#########################################
# ldap used
#########################################
IMAGE_BASE_DN = 'ou=images,cn=clc,o=cloudbot,o=sinobot'
LDAP_CONF_FILE = '/etc/eucalyptus/eucalyptus-ldap.conf'

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
CLUSTER_CONFIG_BASEDN = 'ou=clusterconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
EUCA_CONFIG_BASEDN = 'ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
NODE_CONFIG_BASEDN = 'ou=nodeconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
WEB_CONFIG_BASEDN = 'ou=webconfig,ou=eucaconfig,cn=clc, o=cloudbot, o=sinobot'
CLC_BASEDN = 'cn=clc, o=cloudbot, o=sinobot'
IMAGE_STYLE_BASEDN = 'ou=ImageStyle,cn=clc,o=cloudbot,o=sinobot'
OSNAME_BASEDN = 'ou=OSName,cn=clc,o=cloudbot,o=sinobot'
SNAPSHOT_BASEDN = 'ou=snapshot,cn=clc,o=cloudbot,o=sinobot'
FEATURE_ON = 'on'
ADMIN_POPEDOM = '2'
SERVER_SOURCE_INTV = 10
FEATURE_SUPPORT_AD_USER = '20120528001'
FEATURE_STATIC_USER_RULE = '20120528002'
FEATURE_STATIC_RULE_EXT = '20120528003'
FEATURE_SUPPORT_THERMOPHORESIS = '20120528004'
FEATURE_IMAGE_BY_ISO = '20120528005'
FEATURE_IMAGE_BY_P2V = '20120528006'
FEATURE_SUPPORT_SNAPSHOT = '20120528007'
FEATURE_TRANSFER_ENCRYPT = '20120528008'
FEATURE_IMAGE_BACKUP = '20120528009'
FEATURE_SYSTEM_PARA_PACKUP = '20120528010'
FEATURE_SUPPORT_MOVE_ONLINE = '20120528011'
FEATURE_SUPPORT_LOCAL_USB = '20120528012'
FEATURE_SUPPORT_REMOTE_USB = '20120528013'
FEATURE_SUPPORT_LOCAL_PARALLEL = '20120528014'
FEATURE_SUPPORT_REMOTE_PARALLEL = '20120528015'
FEATURE_SUPPORT_EUCA_USER = '20120528016'
DEFAULT_PASS = 'luhya'
ALL_MEAN = 'all'
ADUSR_ONLY = '0' 
AD_EUCA_BOTH = '1' 
PASSWORD_EXPIRES = 10*365*24*3600
CLOUD_REGISTRY = 'slapd'
SIZE_1KB = 1024
SIZE_1MB = SIZE_1KB * 1024
SIZE_1GB = SIZE_1KB * 1024

SYSTEM_MEMORY_SIZE = SIZE_1GB
SYSTEM_CPU_NUMS = 1
