import getopt, sys, os, stat
import tarfile
import gzip
import Queue
import threading
import time
import datetime
import logging

LOG_PATH     = os.path.expandvars('$HOME') + '/luhya/logs'     # log file root
LOG_FILENAME_ERROR = LOG_PATH+'/paas_ncsensor_error.log'            # log error file name
LOG_FILENAME_INFO = LOG_PATH+'/paas_ncsensor_info.log'               # log info file name
MAX_LOGFILE_SIZE = 100*1024*1024L                              # 100M max lof file size
LOG_ERROR    = 7
LOG_INFO     = 6


# log mutex 
log_mutex = threading.Lock() 

# check paas log file states,if the logf ile is too big then back up the current log file and create new one;
# if there is also a old backup log file, delete it before back up the current log file.
# input: log file name
# output: 0:OK -1:error occur 
def ensure_log_file(logfilepath):
    "ensure_log_file"
    if not os.path.exists(LOG_PATH):
        try:
            os.makedirs(LOG_PATH)
        except:
            print 'Create log root error!'
            return -1
        return 0
    if not os.path.exists(logfilepath):
        return 0
    if (os.path.getsize(logfilepath) > MAX_LOGFILE_SIZE):
        backfilename = '%s.%d' % (logfilepath,1)
        log_mutex.acquire()
        try:
            if os.path.exists(backfilename):
                os.remove(backfilename)
            os.rename(logfilepath,backfilename)
        except:
            print 'ensure lof file error: %s' % logfilepath
            return -1
        log_mutex.release()
    return 0


# paas log function
def paas_log(logstring,level):
    "paas_log"
    if(level == LOG_ERROR):
        ret = ensure_log_file(LOG_FILENAME_ERROR)
        if(ret < 0):
            return -1
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS ERROR:'
        logstr = timestr + logstr +'\n' + logstring+ '\n'
        try:
            fd = open(LOG_FILENAME_ERROR,'a')
            fd.write(logstr)
            fd.close()
        except IOError as e:
            print 'write error-log error:%s' % str(e)
            return -1        
    else:
        ret = ensure_log_file(LOG_FILENAME_INFO)
        if(ret < 0):
            return -1
        now = time.time()
        now = time.localtime(now)
        timestr = time.strftime("%Y-%m-%d %H:%M:%S",now)
        logstr = 'PAAS INFO:'
        logstr = timestr + logstr +'\n' + logstring + '\n'
        try:
            fd = open(LOG_FILENAME_INFO,'a')
            fd.write(logstr)
            fd.close()
        except IOError as e:
            print 'write info-log error:%s' % str(e)
            return -1
    return 0    

def main():
    paas_log('log error',LOG_ERROR)
    paas_log('log info' ,LOG_INFO)

if __name__ == '__main__':
    main()


