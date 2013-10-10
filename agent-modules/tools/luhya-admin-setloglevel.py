#!/usr/bin/env python
import sys

from cloudbot_tools import *


if len(sys.argv)<3:
	print "please input like: luhya-admin-setloglevel.py <clc-ip> <log-level>"
else:	 
    clcip = sys.argv[1]
    log_level = sys.argv[2]
    set_log_level(clcip,log_level)
