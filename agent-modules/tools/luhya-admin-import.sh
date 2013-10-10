#! /bin/sh

LDAP_IP=""
IMPORT_PATH=""
LDAP_ADMIN="cn=admin,o=cloudbot,o=sinobot"
LDAP_PASSWD="ldap4$"
WALRUS_FILTER="ou=walrusconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
NODES_FILTER="ou=nodeconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
CLUSTER_FILTER="ou=clusterconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
PREF_FILTER="ou=prefrencePrompt,cn=clc,o=cloudbot,o=sinobot"
VM_FILTER="ou=virtualmachineconfig,cn=clc,o=cloudbot,o=sinobot"
IMAGES_FILTER="ou=images,cn=clc,o=cloudbot,o=sinobot"
USERS_FILTER="ou=zjut,o=cloudbot,o=sinobot"

USERS_IMPORT_FILE="users.ldif"
PREF_IMPORT_FILE="pref.ldif"
VM_IMPORT_FILE="vm.ldif"
IMAGES_IMPORT_FILE="images.ldif"
CLUSTER_IMPORT_FILE="cluster.ldif"
NODES_IMPORT_FILE="nodes.ldif"
WALRUS_IMPORT_FILE="walrus.ldif"

STR_COMMAND=""

LDAP_PORT=389

usage() {
	echo "$0 [options] [<ldap ip> <import path>]"
	echo "example: $0 --all 192.168.99.100 /root/export"
    echo
    echo "   --help                       this message"
    echo "   --all                        import cloudbot all info"
    echo "   --prefrence                  import cloudbot config info"
    echo "   --users                      import cloudbot users info"
    echo "   --nodes                      import cloudbot nodes info "
    echo "   --cluster                    import cloudbot cluster info "
    echo "   --vms                        import cloudbot vmconfigs info "   
    echo "   --images                     import cloudbot images and imageinfo on ldap"
    echo "   --iso                        import cloudbot iso "
    echo "   --version                    cloudbot version"
    echo
}


import_pref_data() {
	LDIF_FILE=$IMPORT_PATH'/ldap/'$PREF_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then
	    ldapdelete -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN $PREF_FILTER
        ldapadd -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE
        echo "import cloudbot prefrence info to $IMPORT_PATH complete! "
        echo
    else
        echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi
}

import_users_data(){
	LDIF_FILE=$IMPORT_PATH'/ldap/'$USERS_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then
        ldapmodify -a -c -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE
        echo "import cloudbot users info from $LDIF_FILE complete! "
        echo
    else
        echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi
}

import_images_data()
{
	LDIF_FILE=$IMPORT_PATH'/ldap/'$IMAGES_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then       
	    ldapmodify -a -c -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE	    
	else
	    echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi	
}

import_images_file()
{
    WALRUS_IP=$(ldapsearch -D $LDAP_ADMIN -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -b $WALRUS_FILTER -s sub "walrusName=walrus" attributes "hostIPName" -LLL |grep hostIPName|awk '{print $2}')
	if [ -z $WALRUS_IP ]; then
		echo "Get walrus ip from $LDAP_IP is error !"
		echo
		exit 1
	fi
	if [ ! -d $IMPORT_PATH'/images' ]; then
		echo "images will to be import is not found!"
		echo 
		exit 1
	fi
	echo "import image file from $WALRUS_IP"
	scp -r $IMPORT_PATH'/images/*' $WALRUS_IP':/storage/images/'  	
	echo "import cloudbot images to $WALRUS_IP complete! "
	echo
}


import_iso_file()
{
	WALRUS_IP=$(ldapsearch -D $LDAP_ADMIN -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -b $WALRUS_FILTER -s sub "walrusName=walrus" attributes "hostIPName" -LLL |grep hostIPName|awk '{print $2}')
	if [ -z $WALRUS_IP ]; then
	    echo "Get walrus ip from $LDAP_IP is error !"
	    echo
	    exit 1
	fi
	ISO_PATH=$IMPORT_PATH'/iso/'
	echo "import iso file from $ISO_PATH"
	if [ ! -d $ISO_PATH ]; then
        echo "iso will to be import is not found!"
        echo 
        exit 1
	fi
	scp -r $ISO_PATH $WALRUS_IP':/storage/iso/'  
	echo "import cloudbot iso to $WALRUS_IP complete! "
	echo
}


import_nodes_data()
{	
	LDIF_FILE=$IMPORT_PATH'/ldap/'$NODES_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then
        ldapmodify -a -c -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE
        echo "import cloudbot nodes info from $LDIF_FILE complete! "
        echo
    else
        echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi	
}

import_cluster_data()
{
	LDIF_FILE=$IMPORT_PATH'/ldap/'$CLUSTER_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then
        ldapmodify -a -c -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE
        echo "import cloudbot cluster info from $LDIF_FILE complete! "
        echo
    else
        echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi
}

import_vms_data()
{
	LDIF_FILE=$IMPORT_PATH'/ldap/'$VM_IMPORT_FILE
	if [ -f $LDIF_FILE ]; then
        ldapmodify -a -c -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -f $LDIF_FILE
        echo "import cloudbot vmconfig info from $LDIF_FILE complete! "
        echo
    else
        echo "Can't find the ldif file: $LDIF_FILE !"
        echo
	fi
}

import_all()
{
	import_pref_data
	import_users_data
	import_images_data
	import_images_file
	import_iso_file
	import_nodes_data
	import_cluster_data
	import_vms_data
	echo "import cloudbot all complete! "
	echo
}

check_com()
{
    if [ -z $STR_COMMAND ]; then
        usage
        exit 1
    fi
    
    if [ $STR_COMMAND = "-h" -o $STR_COMMAND = "-help" -o $STR_COMMAND = "?" -o $STR_COMMAND = "--help" ]; then
        usage
		exit 1
	fi
	
	if [ $STR_COMMAND = "-a" -o $STR_COMMAND = "--all" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot ! "
			exit 1
		fi
	    import_all
	fi
	
	if [ $STR_COMMAND = "-u" -o $STR_COMMAND = "--users" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot users! "
			exit 1
		fi
	    import_users_data
	fi
	
	if [ $STR_COMMAND = "-p" -o $STR_COMMAND = "--prefrence" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot prefrence! "
			exit 1
		fi
	    import_pref_data
	fi
	
	if [ $STR_COMMAND = "-i" -o $STR_COMMAND = "--images" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot images! "
			exit 1
		fi
	    import_images_data
	    import_images_file	    
	fi
	
	if [ $STR_COMMAND = "-I" -o $STR_COMMAND = "--iso" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot iso! "
			exit 1
		fi
	    import_iso_file
	fi
	
	if [ $STR_COMMAND = "-n" -o $STR_COMMAND = "--nodes" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot nodes info! "
			exit 1
		fi
	    import_nodes_data
	fi
	
	if [ $STR_COMMAND = "-v" -o $STR_COMMAND = "--vms" ]; then
	    if [ -z $IMPORT_PATH ]; then
	        echo "We need 2 parameter for import cloudbot vmconfigs! "
			exit 1
		fi
	    import_vms_data
	fi
	
	if [ $STR_COMMAND = "-V" -o $STR_COMMAND = "--version" ]; then
	    echo "cloudbot2.0 "
	    echo
	fi
	
}
if [ $# -eq 3 ];then
    STR_COMMAND="$1"
    LDAP_IP="$2"
	IMPORT_PATH="$3"
else
    if [ $# -eq 1 ];then
        STR_COMMAND="$1"
    fi
    if [ $# -eq 2 ];then
        STR_COMMAND="$1"
        LDAP_IP="$2"
    fi
fi    

check_com


