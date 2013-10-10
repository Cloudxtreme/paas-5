#!/usr/bin/env python

import sys
import getopt, sys, os, stat
import tarfile
import gzip
import Queue
import thread
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
import random

g_notice_main = -1

class job_thread(threading.Thread):
    def __init__(self, threadCondition):
        threading.Thread.__init__(self)
        self.threadCondition = threadCondition
        
    def run(self):
        global g_notice_main
        for x in range(1,10):
            time.sleep(5)
            print x
        g_notice_main = 1
        self.threadCondition.acquire()
        self.threadCondition.notify()
        self.threadCondition.release()
        print 'after notify'

def main():
    "main"
    print 'starting ...'
    print g_notice_main
    threadCondition = threading.Condition()
    job = job_thread(threadCondition)
    job.setDaemon(True)
    job.start()	
    while True:
        time.sleep(5)
        print 'before wait timed'
        threadCondition.acquire()
        try:
            ret = threadCondition.wait(10)
        except:
            print 'Condition.wait error'
        print 'after wait timed (ret):' 
        print ret
        threadCondition.release()
        print g_notice_main
        if(g_notice_main > 0):
            print 'global value change'
            sys.exit()

if __name__ == '__main__':
    main()


