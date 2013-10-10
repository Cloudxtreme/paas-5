#!/usr/bin/env python

import sys
import getopt, sys, os, stat
import tarfile
import gzip
import Queue
import threading
import time
import datetime
import logging
import string, StringIO
import socket
import fcntl
import struct
import commands
from subprocess import *
import platform
import urllib
import re
import shutil

class nc_pthread_job(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):   
        while(1):
            time.sleep(10)
            print 'i am nc_pthread_job'

class nc_pthrea_main(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        job = nc_pthread_job()
        job.setDaemon(True)
        job.start()
        while (1):
            time.sleep(10)
            print 'i am nc_pthrea_main'

def main():
    "nc-sensor main interface"
    print 'starting ...'
    mp = nc_pthrea_main()
#    mp.setDaemon(True)
    mp.start()
    time.sleep(100)
    print 'main exist ...'
#    thread.exit()
    sys.exit()
    while True:
        print 'my god ,error occur'

if __name__ == '__main__':
    main()



