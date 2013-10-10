import getopt, sys, os, stat
import tarfile
import gzip
import Queue
import threading
import time
import datetime
import logging
import struct

LOG_PATH     = os.path.expandvars('$HOME') + '/luhya/logs'     # log file root
LOG_FILENAME_ERROR = LOG_PATH+'/paas_ncsensor_error.log'       # log error file name
LOG_FILENAME_INFO = LOG_PATH+'/paas_ncsensor_info.log'         # log info file name
MAX_LOGFILE_SIZE = 100*1024*1024L                              # 100M max lof file size
LOG_ERROR    = 7
LOG_INFO     = 6


def main():
    print 'import struct ok!'

if __name__ == '__main__':
    main()