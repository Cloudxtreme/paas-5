#! /bin/sh

LDAP_IP=""
EXPORT_PATH=""
LDAP_ADMIN="cn=admin,o=cloudbot,o=sinobot"
LDAP_PASSWD="ldap4$"
WALRUS_FILTER="ou=walrusconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
NODES_FILTER="ou=nodeconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
CLUSTER_FILTER="ou=clusterconfig,ou=eucaconfig,cn=clc,o=cloudbot,o=sinobot"
PREF_FILTER="ou=prefrencePrompt,cn=clc,o=cloudbot,o=sinobot"
VM_FILTER="ou=virtualmachineconfig,cn=clc,o=cloudbot,o=sinobot"
IMAGES_FILTER="ou=images,cn=clc,o=cloudbot,o=sinobot"
USERS_FILTER="ou=zjut,o=cloudbot,o=sinobot"

USERS_EXPORT_FILE="users.ldif"
PREF_EXPORT_FILE="pref.ldif"
VM_EXPORT_FILE="vm.ldif"
IMAGES_EXPORT_FILE="images.ldif"
CLUSTER_EXPORT_FILE="cluster.ldif"
NODES_EXPORT_FILE="nodes.ldif"
WALRUS_EXPORT_FILE="walrus.ldif"

STR_COMMAND=""

LDAP_PORT=389

usage() {
	echo "$0 [options] [<ldap ip> <export path>]"
	echo "example: $0 --all 192.168.99.100 /root/export"
    echo
    echo "   --help                       this message"
    echo "   --all                        export cloudbot all info"
    echo "   --prefrence                  export cloudbot config info"
    echo "   --users                      export cloudbot users info"
    echo "   --nodes                      export cloudbot nodes info "
    echo "   --cluster                    export cloudbot cluster info "
    echo "   --vms                        export cloudbot vmconfigs info "   
    echo "   --images                     export cloudbot images and imageinfo on ldap"
    echo "   --iso                        export cloudbot iso "
    echo "   --version                    cloudbot version"
    echo
}


export_pref_data() {
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $PREF_FILTER >$EXPORT_PATH'/ldap/'$PREF_EXPORT_FILE

	echo "Export cloudbot prefrence info to $EXPORT_PATH complete! "	
}

export_users_data(){
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $USERS_FILTER >$EXPORT_PATH'/ldap/'$USERS_EXPORT_FILE
	echo "Export cloudbot users info to $EXPORT_PATH complete! "
}

export_images_data()
{
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $IMAGES_FILTER >$EXPORT_PATH'/ldap/'$IMAGES_EXPORT_FILE
}

export_images_file()
{	
	WALRUS_IP=$(ldapsearch -D $LDAP_ADMIN -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -b $WALRUS_FILTER -s sub "walrusName=walrus" attributes "hostIPName" -LLL |grep hostIPName|awk '{print $2}')
	if [ -z $WALRUS_IP ]; then
	    echo "Get walrus ip from $LDAP_IP is error !"
	    echo
	    exit 1
	fi
	if [ ! -d $EXPORT_PATH'/images' ]; then
        mkdir -p $EXPORT_PATH'/images'
	fi
	
	echo "Export image file from $WALRUS_IP"
	scp -r $WALRUS_IP':/storage/images/*' $EXPORT_PATH'/images/' 	
	echo "Export cloudbot images to $EXPORT_PATH complete! "
	echo
}

export_iso_file()
{
	WALRUS_IP=$(ldapsearch -D $LDAP_ADMIN -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -b $WALRUS_FILTER -s sub "walrusName=walrus" attributes "hostIPName" -LLL |grep hostIPName|awk '{print $2}')
	if [ -z $WALRUS_IP ]; then
	    echo "Get walrus ip from $LDAP_IP is error !"
	    echo
	    exit 1
	fi
	
	echo "Export iso file from $WALRUS_IP"
	if [ ! -d $EXPORT_PATH'/iso' ]; then
        mkdir -p $EXPORT_PATH'/iso'
	fi
	scp -r $WALRUS_IP':/storage/iso/*' $EXPORT_PATH'/iso/' 
	echo "Export cloudbot iso to $EXPORT_PATH complete! "
	echo
}


export_nodes_data()
{
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $NODES_FILTER >$EXPORT_PATH'/ldap/'$NODES_EXPORT_FILE

	echo "Export cloudbot nodes info to $EXPORT_PATH complete! "
	echo	
}

export_cluster_data()
{
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $CLUSTER_FILTER >$EXPORT_PATH'/ldap/'$CLUSTER_EXPORT_FILE

	echo "Export cloudbot cluster info to $EXPORT_PATH complete! "
	echo
}

export_vms_data()
{
	if [ ! -d $EXPORT_PATH'/ldap' ]; then
        mkdir -p $EXPORT_PATH'/ldap'
	fi
	ldapsearch -h $LDAP_IP -p $LDAP_PORT -w $LDAP_PASSWD -D $LDAP_ADMIN -b $VM_FILTER >$EXPORT_PATH'/ldap/'$VM_EXPORT_FILE

	echo "Export cloudbot vmconfig info to $EXPORT_PATH complete! "
	echo
}

export_all()
{
	export_pref_data
	export_users_data
	export_images_data
	export_images_file
	export_iso_file
	export_nodes_data
	export_cluster_data
	export_vms_data
	echo "Export cloudbot all complete! "
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
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot data! "
			exit 1
		fi
	    export_all
	fi
	
	if [ $STR_COMMAND = "-u" -o $STR_COMMAND = "--users" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot users! "
			exit 1
		fi
	    export_users_data
	fi
	
	if [ $STR_COMMAND = "-p" -o $STR_COMMAND = "--prefrence" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot prefrence! "
			exit 1
		fi
	    export_pref_data
	fi
	
	if [ $STR_COMMAND = "-i" -o $STR_COMMAND = "--images" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot images! "
			exit 1
		fi
	    export_images_data
	    export_images_file
	fi
	
	if [ $STR_COMMAND = "-I" -o $STR_COMMAND = "--iso" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot iso! "
			exit 1
		fi
	    export_iso_file
	fi
	
	if [ $STR_COMMAND = "-n" -o $STR_COMMAND = "--nodes" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot nodes info! "
			exit 1
		fi
	    export_nodes_data
	fi
	
	if [ $STR_COMMAND = "-v" -o $STR_COMMAND = "--vms" ]; then
	    if [ -z $EXPORT_PATH ]; then
	        echo "We need 2 parameter for export cloudbot vmconfigs! "
			exit 1
		fi
	    export_vms_data
	fi
	
	if [ $STR_COMMAND = "-V" -o $STR_COMMAND = "--version" ]; then
	    echo "cloudbot2.0 "
	    echo
	fi
	
}
if [ $# -eq 3 ];then
    STR_COMMAND="$1"
    LDAP_IP="$2"
	EXPORT_PATH="$3"
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




