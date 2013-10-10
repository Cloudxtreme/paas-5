import ldap
import ldap.modlist as modlist
import getopt, sys, os, stat,commands
import time


def _get_image_len(image_path,image_id):
    image_len = -1
    if os.path.exists(image_path+image_id):
    	stat = os.stat(image_path+image_id+'/machine')
    	if stat!=None:
    		image_len = stat.st_size
    return image_len

def _login_ldap(ldap_ip):
    try:
        l = ldap.open(ldap_ip)
        l.protocol_version = ldap.VERSION3
        l.simple_bind('admin', 'ldap4$')
    except  ldap.LDAPError, e:
        return None
    return l

def _add_to_ldap(ldap_ip,attrs):
    l = _login_ldap(ldap_ip)
    if(l != None):
        try:
            ldif = modlist.addModlist(attrs)
            l.add_s(newDN, ldif)
        except ldap.LDAPError, e:
            print('p_add_to_ldap is error !')
        l.unbind_s()


def _write_image_ldap(ldap_ip,image_id,image_name,image_len):
    newDN = 'imageId=' + image_id + ',' + 'ou=images,cn=clc,o=cloudbot,o=sinobot'
    attrs = {}
    attrs['objectclass'] = ['IMG']
    attrs['imageId'] = image_id
    attrs['name'] = image_name
    attrs['imageLocation'] = '/storage/images'
    attrs['imageState'] = 'avalible' 
    attrs['ownerid'] = 'admin'         
    attrs['ImageStyle'] = 'desktop' 
    attrs['platform'] = 'windows'
    attrs['OS'] = 'windows'                       
    attrs['public'] = 'TRUE'
    attrs['imageCategory'] = '1'
    attrs['description'] = 'windows'  #set default value
    attrs['vmStyle'] = 'm1.small'
    attrs['createTime'] = str(int(time.time()))
    attrs['size'] = str(image_len) 
    attrs['HYPERVISOR'] = 'kvm'            
    _add_to_ldap(newDN, attrs)

def _change_image_attr(image_path,image_id):
    cmd_line = 'chmod 777 ' +image_path+image_id
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    print(cmd_output)
    cmd_line = 'chmod 777 ' +image_path+image_id+'/machine'
    cmd_status, cmd_output = commands.getstatusoutput(cmd_line)
    print(cmd_output)

def _copy_image_to_walrus(walrus_ip,image_path,image_id):
    cmd_line = 'scp -r ' +image_path+image_id +' '+walrus_ip+':/storage/images/'
    cmd_status,cmd_output = commands.getstatusoutput(cmd_line)

def append_image(ldap_ip,walrus_ip,image_path,image_id,image_name):
    image_len = _get_image_len(image_path,image_id)
    if image_len >0 :
        _write_image_ldap(ldap_ip,image_id,image_name,image_len)
        _change_image_attr(image_path,image_id)
        _copy_image_to_walrus(walrus_ip,image_path,image_id)
    else:
        print('image not exist or is error!')


append_image('192.168.2.180','192.168.2.181','/root/images/','emi-5C1034FA','test windows xp')