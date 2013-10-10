#!/usr/bin/env python
import sys

from cloudbot_tools import *


if len(sys.argv)<3:
	print "please input like: luhya-admin-dump-clc.py <clc-ip> <data-name>"
else:	 
    clcip = sys.argv[1]
    dump_data = sys.argv[2]
    res = get_clc_data(clcip,dump_data)
    print res
