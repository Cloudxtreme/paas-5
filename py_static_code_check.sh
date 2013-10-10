#! /bin/sh 
SCAN_DIR=$1

rm /tmp/pycodecheck.log 

if [ "$SCAN_DIR"x == "x" ]; then
    SCAN_DIR="./"
fi

py_file_list=`find $SCAN_DIR -name *.py`

for py_file in $py_file_list
do
    echo "Now scanning $py_file"
    pylint --include-ids=y --disable-msg=W0122,W0702,C0103,C0111 $py_file >> /tmp/pycodecheck.log
done

vi /tmp/pycodecheck.log

