from cloudbot.interface.ttypes import *

class VM_ENGINE:    # used like enum
    TYPE_000 = 0
    TYPE_001 = 1
    TYPE_010 = 2
    TYPE_011 = 3
    TYPE_100 = 4
    TYPE_101 = 5
    TYPE_110 = 6
    TYPE_111 = 7
    
class vm_engine_data:
    images=[]
    vmconfigs = []
    userList = []
    nodeList = []
    
class run_instance_data:
    user = None
    image_id = None
    node_ip = None
    