#! /bin/sh
IMAGE_PATH=""
IMAGE_LEN=""
IMAGE_ID=""
IMAGE_NAME=""
LADP_IP=""
WALRUS_IP=""
usage() {
	echo "$0 <image path> <image id> <image name> <ldap ip> <walrus ip>"
    echo
}


if [ $# -eq 0 ]; then
        usage
        exit 1
fi

if [ $5 != "" ]; then
	IMAGE_PATH="$1"
	IMAGE_ID="$2"
	IMAGE_NAME="$3"
	LDAP_IP="$4"
	WALRUS_IP="$5"

	if [ -f $IMAGE_PATH'/machine' ]; then
		IMAGE_LEN=`ls $IMAGE_PATH'/machine' -l|awk {'print $5'}`
		rm /tmp/image.ldif
        CREATE_TIME=`date +%s`
	    echo "dn: imageId=$IMAGE_ID,ou=images,cn=clc,o=cloudbot,o=sinobot" >>/tmp/image.ldif
		echo "objectClass: IMG" >> /tmp/image.ldif
		echo "HYPERVISOR: kvm" >> /tmp/image.ldif
		echo "createTime: $CREATE_TIME" >>/tmp/image.ldif
		echo "imageId: "$IMAGE_ID >>/tmp/image.ldif
		echo "imageState: available" >> /tmp/image.ldif
		echo "vmStyle: m1.small" >>/tmp/image.ldif
		echo "imageLocation: /storage/images/" >>/tmp/image.ldif
		echo "ownerid: admin" >> /tmp/image.ldif
		echo "size: "$IMAGE_LEN >>/tmp/image.ldif
		echo "OS: windows" >>/tmp/image.ldif
		echo "public: TRUE" >>/tmp/image.ldif
		echo "ImageStyle: Desktop" >>/tmp/image.ldif
		echo "name: "$IMAGE_NAME >>/tmp/image.ldif
		echo "imageCategory: 1" >>/tmp/image.ldif
		echo "description: no description" >>/tmp/image.ldif
		echo "platform: windows" >>/tmp/image.ldif

        cat /tmp/image.ldif

		ldapadd -h $LDAP_IP -p 389 -w ldap4$ -D 'cn=admin,o=cloudbot,o=sinobot' -f /tmp/image.ldif
	    
	    mkdir $IMAGE_PATH$IMAGE_ID
	    chmod 777 $IMAGE_PATH$IMAGE_ID
	    chown eucalyptus:eucalyptus $IMAGE_PATH$IMAGE_ID
	    mv $IMAGE_PATH'machine' $IMAGE_PATH$IMAGE_ID
	    chmod 777 $IMAGE_PATH$IMAGE_ID'/machine'
	    chown eucalyptus:eucalyptus $IMAGE_PATH$IMAGE_ID'/machine'
	    
	    scp -r $IMAGE_PATH$IMAGE_ID eucalyptus@$WALRUS_IP:/storage/images/
	fi
fi


