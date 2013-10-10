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

class Maker(threading.Thread): 
    def __init__(self,threadName,shareObject):
        threading.Thread.__init__(self,name=threadName)
        self.shareObject=shareObject
        
    def run(self):
        for x in range(1,5):
            time.sleep(random.randrange(1,4))
            self.shareObject.set(x)
            print "%s threading write %d" %(threading.currentThread().getName(),x)
class User(threading.Thread):
    def __init__(self,threadName,shareObject):
        threading.Thread.__init__(self,name=threadName)
        self.shareObject=shareObject
        self.sum=0
        
    def run(self):
        for x in range(1,5):
            time.sleep(random.randrange(1,4))
            tempNum=self.shareObject.get()
            print "%s threading read %d" %(threading.currentThread().getName(),tempNum)
            self.sum=self.sum+tempNum
            
    def display(self):
        print "sum is %d" %(self.sum)

class ShareInt():
    
    def __init__(self):
        self.threadCondition=threading.Condition()
        self.shareObject=[]
       
    def set(self,num):
        self.threadCondition.acquire()      
        if len(self.shareObject)!=0:
            print "%s threading try write! But shareObject is full" %(threading.currentThread().getName())
            self.threadCondition.wait()     
        self.shareObject.append(num)
        
        self.threadCondition.notify()     
        self.threadCondition.release()
                                         
    def get(self):
        self.threadCondition.acquire()
        
        if len(self.shareObject)==0:
            print "%s threading try read! But shareObject is empty" %(threading.currentThread().getName())
            self.threadCondition.wait()
            
        tempNum=self.shareObject[0]
        self.shareObject.remove(tempNum)
        self.threadCondition.notify()
        self.threadCondition.release()
        return tempNum

def main():
    shareObject=ShareInt()
    user1=User("user1",shareObject)
    maker1=Maker("maker1",shareObject)
    
    user1.start()
    maker1.start()
    
    user1.join()
    maker1.join()
    
    user1.display()

if __name__ == '__main__':
    main()


