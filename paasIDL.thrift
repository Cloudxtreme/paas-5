namespace cpp CloudbotWebManagement
namespace py CloudbotWebManagement
namespace c_glib CloudbotWebManagement
namespace php CloudbotWebManagement

const i32 MAJOR_VERSION=1
const i32 MINOR_VERSION=0

enum thd_SERVICE_TYPE
{
    CLOUD_REGISTRY,
    CLOUD_WEB,
    CLOUD_CLC,
    CLOUD_CC,
    CLOUD_WALRUS,
    CLOUD_NC,
    CLOUD_IFOLDER
}

struct thd_hard_source
{
        1: i64           cpu_num             
        2: i64           cpu_utilization
        3: string        cpu_frequenc    
        4: i64           total_memory    /* MB */
        5: i64           user_memory     /* MB */
        6: i64           free_memory     /* MB */
        7: i64           total_disk      /* GB */
        8: i64           user_disk       /* GB */
        9: i64           free_disk       /* GB */
        10:i64           net_receiverate /* kB/s */
        11:string        ip_address
        12:string        state           /* HW_STATUS_OK, HW_STATUS_WARN */
        13:string        cpu_style
        14:i64           net_sendrate    /* kB/s */
}

struct thd_service
{
    1:thd_SERVICE_TYPE  service_id
    2:bool          is_alive
}

struct thd_service_list
{
    1:thd_hard_source       resource
    2:list<thd_service>     paas_services
}


struct thd_backup_transaction
{
    1: string    transaction_id
    2: string    state              /* 'INIT' : waiting for backup                */
                                    /* 'DUPLICATING': now is backup                       */
                                    /* 'BACKUP_FINISH': backup is finished         */
                                    /* 'BACKUP_FAILED' :  backup is failed           */  
    3: string    user_name
    4: string    image_id
    5: string    instance_id
    6: string    machine_name
    7: string    node_ip
    8: i64       progress
}

enum  thd_TRANSACT_STATE
{
        INIT,
        DOWNLOADING,
        DOWNLOAD_FINISHED,
        DOWNLOAD_FAILED,
        PENDING,
        RUNNING,
        RUN_FAILED,
        SHUTTING_DOWN,
        TERMINATED,
        SUBMITTING,
        SUBMIT_FAILED,
        SUBMIT_FINISHED
}


struct thd_instance_info
{
    1:  string               instance_id
    2:  string               image_id
    3:  string               user
    4:  thd_TRANSACT_STATE   state
    5:  i64                  n_port
    6:  string               str_password
}

struct thd_file
{
    1:  string      fileName
    2:  i64         createTime      /* number of second */
    3:  i64         size            /* byte */
}


struct thd_run_schedule
{
    1: string   run_model         /* manual; auto */
    2: string   power_on_time
    3: string   power_off_time 
}


struct thd_net_info
{
    1: string  domain
    2: string  net_mode  /* NAT; BRIDGE */ 
    3: bool    ip_dhcp
    4: bool    dns_dhcp    
    5: string  public_ip
    6: string  private_ip
    7: string  public_mac
    8: string  private_mac
    9: string  gateway
    10:string  netmask
    11:string  dns
    12:string  wins
    
}

struct thd_vm_info
{
    1:  i64         vm_cpu
    2:  i64         vm_memory   /* MB */
    3:  i64         vm_disk     /* GB */
    4:  string      machine_name
    5:  string      vm_protocol      /* spice; vnc;  ssh */
    6:  string      display_mode     /* full screen; window ; no display */
    7:  bool        is_clear_power_off  /* if node ip not set, this always True */
    8:  i64         vm_port 
    9:  string      vm_password
    10: bool        is_run_without_copy  /* run instance no copy */
    11: bool        is_permit_write_file_to_image
    12: i64         number_of_screens    /* can be any spices connect */
}

struct thd_peripheral 
{
    1: bool      is_support_peripheral
    2: bool      is_support_usb
    3: i64       max_usb_number
    4: bool      is_support_parallel
    5: bool      is_support_com
    6: bool      is_cdrom
    7: bool      is_external_device
    8: i64       external_disk
}

struct thd_support_snapshot
{
    1: bool        is_snapshot
    2: i64         max_snapshot
}


struct thd_thermophoresis
{
    1:  bool                    is_thermophoresis
    2:  string                  thermophoresis_cluster
    3:  string                  thermophoresis_node    
}

struct thd_instance_state
{    
    1:  string    instance_type           /* desktop ; server */
    2:  bool      is_can_run        
    3:  i64       download_progress
    4:  thd_TRANSACT_STATE  state
    5:  bool      is_local     
}

struct thd_vmConfig
{
    1:  string                  id                  /* the vmconfig identification , uuid  */
    2:  string                  user
    3:  i64                     user_department_id
    4:  string                  image_id   
    6:  bool                    is_assign_node
    7:  string                  node_ip
    8:  thd_thermophoresis      thermophoresis
    9:  thd_run_schedule        run_schedule
    10: thd_net_info            net_info
    11: thd_vm_info             vm_info
    12: thd_support_snapshot    snapshot
    13: thd_peripheral          peripheral
}


struct thd_client_info
{
        1: string                  client_data_id
        2: string                  image_id
        3: string                  user
        4: string                  node_ip
        5: i64                     user_department_id /* -1 : default,any department ; departmentid */       
        6: string                  os_type    /* windows xp ; windows 2003;windows 7 ... */
        7: string                  platform   /* windows ; linux ; macos */
        8: i64                     image_category  /* 0: private 1: public 1000+departmentId : department image */
        9: i64                     image_size       /* byte */      
        10:thd_thermophoresis      thermophoresis
        11:thd_run_schedule        run_schedule
        12:thd_net_info            net_info
        13:thd_vm_info             vm_info
        14:thd_support_snapshot    snapshot
        15:thd_peripheral          peripheral
        16:thd_instance_state      instance_state 
        17:string                  vmconfig_id
        18:bool                    is_assign_node
        19:string                  image_name
        20:bool                    run_as_super       
}

struct thd_run_instance_ret
{
     1: string  node_ip
     2: i64     return_value
}


struct  thd_NodeInfo
{
    1:  string          hostIp
    2:  string          clusterName
    3:  i64             freeCPUs
    4:  i64             freeDisk     /* GB */
    5:  i64             freeMem      /* MB */
    6:  i64             totalCPUs
    7:  i64             totalDisk    /* GB */
    8:  i64             totalMem     /* MB */
    9:  bool            isLocal
}

struct thd_ClusterInfo
{
    1:  string          clusterName
    2:  string          hostIp
    3:  string          HYPERVISOR
}


struct thd_DomainInfo
{
    1:  string          domain
    2:  string          domainHost
    3:  string          UserNAME
    4:  string          encryptedPassword
    5:  string          baseDN
    6:  i64             port
}



struct thd_ImageInfo
{
    1: string imageId
    2: string imageLocation
    3: string imageState
    4: string imageOwnerId
    5: string architecture
    6: string imageType     /* desktop ; server */
    7: string kernelId
    8: string ramdiskId
    9: i64 isPublic
    10: string signature
    11: string name
    12: i64 imageCategory
    13: string description
    14: string platform  /* windows xp ; windows 7 ; windows 2003 ...*/
    15: string ownerName
    16: string vmStyle 
    17: string Groups
    18: string OS       /* windows ; linux ; macOS ...*/
    19: string createTime   /* number of second */
    20: i64 size        /* byte */
    21: string manifest
    22: string HYPERVISOR
}

struct thd_UserInfo
{
    1: string       userName        /* the server used name */
    2: string       email
    3: string       realName        
    4: i64          reservationId
    5: string       bCryptedPassword
    6: string       telephoneNumber
    7: string       affiliation
    8: string       projectDescription
    9: string       projectPIName
    10: string      confirmationCode    
    11: string      certificateCode
    12: bool        isApproved      
    13: bool        isConfirmed     
    14: bool        isEnabled                       
    15: bool        isAdministrator             
    16: i64         passwordExpires                 
    17: string      temporaryPassword           
    18: bool        isPrivateImgCreated      
    19: i64         popedom             
    20: string      sLogonName          /* display name */      
    21: string      sSeriesName     
    22: i64         seriesID
    23: string      domain
    24: i64         maxPrivateInstances
}

enum thd_SubmitState
{
    PENDING,
    COMBINING,
    UPLOADING,
    REGISTERING,
    FAILED,
    FINISHED
}

enum thd_port
{
    THRIFT_CC_PORT=9090,
    THRIFT_NC_PORT=9091,
    THRIFT_CLC_PORT,
    THRIFT_WALRUS_PORT,
    THRIFT_LDAP_PORT,
    THRIFT_DESKTOP_PORT,
    THRIFT_IFOLDER_PORT
}


struct thd_SubmitImageInfo
{
    1:string                     submitID
    2:thd_ImageInfo              newImage
    3:string                     baseImageID
    4:thd_SubmitState            state
    5:i64                        progress
    6:i64                        imageSize            /* byte */
    7:i64                        uploadProgress
    8:i64                        uploadSpeed
    9:string                     remainingTime       /* number of second */
}


struct thd_Transaction
{
        1:string               transactionID 
        2:string               imageID                    /* createMode为ISO时: iso文件名(不含路径不含扩展名) , createMode为P2V时: p2v/v2v文件名(不含路径不含扩展名) , createMode为IMG时: imageId */
        3:thd_TRANSACT_STATE    state
        4:string               instanceID
        5:i64                  instancePort
        6:string               instancePassword
        7:i64                  downloadProgress
        8:string               submitTime               /* number of second */
        9:thd_SubmitState      submitState
        10:i64                 submitProgress
        11:i64                 imageSize                 /* byte */
        12:i64                 uploadProgress
        13:i64                 uploadSpeed
        14:string              user
        15:thd_ImageInfo       newImageInfo
        16:string              sumbitEstimatedTime    /* number of second */
        17:string              modifyTime              /* number of second */
        18:i64                 vmcpu                        /* cpu of instance :  for create image by iso */
        19:i64                 vmmemory                     /* memory of instance :  for create image by iso */
        20:i64                 vmdisk                       /* disk of instance :  for create image by iso */
        21:string              createMode                   /* create image mode: ISO:从ISO创建镜像文件 P2V:从p2v/v2v文件创建镜像文件 IMG : 从镜像模板创建镜像文件 */
        22:string              platform                     /* the platform of iso or p2v/v2v file */
        23:string              bootFrom                     /* start the instance boot from */ 
}

struct thd_eucaTransaction
{
        1:string               transactionID 
        2:string               imageID
        3:thd_TRANSACT_STATE    state
        4:string               instanceID
        5:i64                  instancePort
        6:string               instancePassword
        7:i64                  downloadProgress
        11:i64                 imageSize           /* byte */
        14:string              user
        15:string              nodeIp
        16:string              modifyTime          /* number of second */
}

struct thd_transmit_data
{
    1: string node_ip
    2: list<thd_eucaTransaction> transactions
}

enum  thd_MIGRATESTATE
{
        INIT,
        MIGRATTING,
        MIGRATE_FINISHED,
        MIGRATE_FAILED,
        MIGRATE_FORBIDDEN
}

struct thd_migrateInfo
{
      1:string    transactionID
      2:string    sourceIP
      3:string    targetIP 
      4:string    publicIp
      5:string    machinename
      6:string    user
      7:string    imageId
      8:bool      isMigrated
}


struct  thd_nodeMigrateInfo
{
    1:string         id
     2:  string         sourceIP
     3:  string         targetIP
}

struct thd_snapshot
{
    1:string    imageID
    2:string    userName
    3:string    snapshotName
    4:string    description
    5:i64       id
    6:string    snapshotTag
    7:i64       vmSize       
    8:string    snapshotDate
}


service ldapApi{
	string luhya_reg_getClcIp();
    string luhya_reg_get_clc_host();
	bool luhya_reg_judgeUser(1:string userName, 2:string password);
	list<thd_ClusterInfo> luhya_reg_getClusterList();
	list<thd_NodeInfo> luhya_reg_getNodeList();
	list<thd_NodeInfo> luhya_reg_getNodeInfoByCluster(1:string clusterName);
	list<thd_UserInfo> luhya_reg_getUserList();
	list<thd_UserInfo> luhya_reg_get_client_user();
	list<string> luhya_reg_getUserNameList();
	list<thd_UserInfo> luhya_reg_get_users_by_department(1:i64 department);
	list<thd_ImageInfo> luhya_reg_getImageList();
	thd_ImageInfo luhya_reg_getImageInfo(1:string imageID);
	bool luhya_reg_updateImageInfo(1:thd_ImageInfo imageInfo);
	bool luhya_reg_addImageInfo(1:thd_ImageInfo newImageInfo);
	bool luhya_reg_deleteImage(1:string imageID);
	string luhya_reg_getWalrusIp();
    string luhya_reg_getWalrusPort();
	string luhya_reg_getWalrusBucketPath();
	string luhya_reg_getImageXml(1:string imageID);
	list<string> luhya_reg_getCategoryList ();
	list<string> luhya_reg_getImageTypeList ();
	list<string> luhya_reg_getOSTypeList ();
	string luhya_reg_getMakeImageNode();
	string luhya_reg_getUserSecretKey(1:string userName);
	string luhya_reg_getUserQueryId(1:string userName);
    string luhya_reg_getCertificateCode(1:string userName);
    i64 luhya_reg_getMakeImageResource();
    
    
    /*  function : the domain user logon the system                                     */
    /*  para:      string     userName         the user name                            */
    /*             string     password         the user password                        */
    /*             string     domain           the user domain                          */
    /*  return     i64         0  :     success                                         */
    /*                        -1  :     can't connect to AD                             */
    /*                        -2  :     the user name or password is error              */
    /*                        -3  :     get user info from AD is error                  */
    /*                         -4  :     add the AD user to ldap (euca user) is error   */
    /*                         -5 :   have no this user                                 */
    i64 euca_reg_domain_user_logon(1:string userName,2:string password,3:string domain);
    
    /*  function : get the image list for the user can used                            */
    /*  para:      string     userName         the user name                           */
    /*  return     list<thd_ImageInfo>         the list of image for user can used     */
    list<thd_ImageInfo> euca_reg_getImageList(1:string userName);
    
    /*  function : get the vm config                                                   */
    /*  para:      string     userName         the user name                           */
    /*             string     imageId          the Id of image                         */
    /*  return     thd_vmConfig         the vm config for the image of user            */
    thd_vmConfig euca_reg_get_vmconfig(1:thd_vmConfig vmconfig );
    
    list<thd_vmConfig> euca_reg_get_all_vmconfig();
    
    list<thd_vmConfig> euca_reg_get_vmconfig_by_node(1:string nodeIp);
    
    list<thd_vmConfig> euca_reg_get_vmconfig_by_cluster(1:string clusterName);
    
    thd_vmConfig euca_reg_get_vmconfig_by_id(1:string id);
    
    /* change the vm config , vmconfig.id should be set */
    bool euca_reg_change_vmconfig(1:thd_vmConfig vmconfig);
     
    /* add the vm config , vmconfig.id not set                                    */
    /* return value:   0     success                                              */
    /*                 -1    add vmconfig to ldap error                           */
    /*                 -2    is Thermophoresis node,and the node have no resource */
    /*                 -3    the input vmconfig is error                          */ 
    i64 euca_reg_add_vmconfig(1:thd_vmConfig vmconfig);
    
    /* delete the vm config , vmconfig.id should be set */
    bool euca_reg_delete_vmconfig(1:thd_vmConfig vmconfig);
    
    /* to get the feature is available */
    bool luhya_reg_get_feature_status(1:string featureID );                  
    
    /* to get the images for the user can use */
    list<thd_ImageInfo> luhya_reg_get_available_image_list(1:string userName);
    
    bool luhya_reg_is_support_thermophoresis();
    
    bool luhya_reg_is_support_remote_usb();
    
    bool luhya_reg_is_support_remote_parallel();
    
    bool luhya_reg_is_support_local_usb();
    
    bool luhya_reg_is_support_local_parallel();
    
    bool luhya_reg_can_extdisk();
    
    bool luhya_reg_can_create_img_from_iso();
    
    bool luhya_reg_can_create_img_from_p2v();
    
    bool luhya_reg_support_ad_user();
    
    bool luhya_reg_can_snapshot();
    
    i64 luhya_reg_get_department_by_user(1:string userName);
    
    thd_NodeInfo luhya_reg_get_nodeinfo_by_nodeIp(1:string nodeIp);
    thd_ClusterInfo luhya_reg_get_clusterinfo_by_cluster(1:string clusterName);
    bool euca_reg_delete_vmconfig_by_node(1:string nodeIp);
    
    bool luhya_reg_add_department(1:string department);
    bool luhya_reg_delete_department(1:string department);
    bool luhya_reg_department_can_be_delete(1:string department);
    list<thd_vmConfig> euca_reg_get_vmconfigs_by_user(1:string userName);

    list<thd_DomainInfo> luhya_reg_get_all_domains();
    thd_DomainInfo luhya_reg_get_domain_by_name(1:string domain);
    bool luhya_reg_add_domain(1:thd_DomainInfo domInfo);
    bool luhya_reg_modify_domain(1:thd_DomainInfo domInfo);
    bool luhya_reg_del_domain(1:thd_DomainInfo domInfo);
    bool luhya_reg_add_user(1:thd_UserInfo userInfo);
    bool luhya_reg_modify_user(1:thd_UserInfo userInfo);
    i64 luhya_reg_delete_user(1:string userName);
    
    bool luhya_reg_is_admin(1:string userName);
    
    thd_hard_source luhya_reg_get_current_resource();
    
    list<string> luhya_reg_get_all_service_ip();
    list<thd_SERVICE_TYPE> luhya_reg_get_services_by_ip(1:string ipAddress);
    bool  luhya_reg_is_service_start();
    bool  luhya_reg_start_service();
    bool  luhya_reg_stop_service();
   
    /* live migragte */
    list<thd_nodeMigrateInfo> luhya_reg_get_node_migrate_list();
    bool luhya_reg_delete_node_migrate_pair(1:string sourceIP, 2:string targetIP);
    bool luhya_reg_add_node_migrate_pair(1:string sourceIP, 2:string targetIP);
    list<thd_migrateInfo> luhya_reg_get_migrate_Info_list(1:string userName);

    /*  snapshot api */
    i64 luhya_reg_get_available_snapshot_num(1:string userName, 2:string imageID);
    i64 luhya_reg_get_current_snapshot_id(1:string userName, 2:string imageID);
    bool luhya_reg_set_current_snapshot_id(1:string userName, 2:string imageID, 3:i64 snapshotID);
    list<thd_snapshot> luhya_reg_get_snapshot_list(1:string userName, 2:string imageID);
    thd_snapshot luhya_reg_get_snapshotInfo_by_id(1:string userName, 2:string imageID, 3:i64 snapshotID);
    bool luhya_reg_add_snapshot(1:thd_snapshot snapshotInfo);
    bool luhya_reg_modify_snapshot(1:thd_snapshot snapshotInfo);
    bool luhya_reg_delete_snapshot(1:string userName, 2:string imageID, 3:i64 snapshotID);
    i64  luhya_reg_get_available_snapshot_id(1:string userName, 2:string imageID);
    
    thd_ClusterInfo luhya_reg_get_clusterInfo_by_ccIp(1:string ccIp);

    bool luhya_reg_set_make_image_node(1:string nodeIp);

    bool luhya_reg_init_clc_info(1:string clcIp);
    bool luhya_reg_init_walrus_info(1:string walrusIp);
    bool luhya_reg_init_cluster_info(1:thd_ClusterInfo clusterInfo);
    bool luhya_reg_init_node_info(1:thd_NodeInfo nodeInfo);
    
    string luhya_reg_get_ins_report_intv();
    
    bool luhya_reg_is_registered(1:thd_SERVICE_TYPE servID,2:string hostIp);
    
    i64 luhya_reg_get_max_private_instances(1:string user);
    bool luhya_reg_is_online();
    thd_UserInfo luhya_reg_get_user_info(1:string userName);
    bool luhya_reg_is_image_used(1:string imageID);
}

service clcApi{
	
	list<thd_client_info> luhya_res_get_live_instances(1:string userName);
	list<thd_client_info> luhya_res_get_instances_by_node(1:string userName,2:string nodeIp);
	/* instances : only filled user imageId instanceId     */
    bool luhya_res_backup_instances(1:list<thd_client_info> instances);
    /* instances : only filled user imageId instanceId     */
    bool luhya_res_stop_backup_instance(1:string transactionID );
    bool luhya_res_stop_backup_instance_by_node(1:string nodeIp );
    
    bool luhya_res_set_backup_state(1:string user,2:string imageID, 3:string state);
    bool luhya_res_set_backup_progress(1:string user,2:string imageID, 3:i64 progress);
    
    list<thd_backup_transaction> luhya_res_get_all_backup_transactions();
    thd_backup_transaction luhya_res_get_backup_transaction_by_id(1:string transactionID);
    
    /* instances : only filled user imageId instanceId     */
    bool luhya_res_restore_instances(1:list<thd_client_info> instances);
    bool luhya_res_set_restore_state(1:string user,2:string imageID, 3:string state);
    bool luhya_res_set_restore_progress(1:string user,2:string imageID, 3:i64 progress);
    list<thd_backup_transaction> luhya_res_get_all_restore_transactions();
    thd_backup_transaction luhya_res_get_restore_transaction_by_id(1:string transactionID);
    
    thd_hard_source luhya_res_clc_get_current_resource();
    bool  luhya_res_clc_is_service_start();
    bool  luhya_res_clc_start_service();
    bool  luhya_res_clc_stop_service();
    /* live migragte */
    list<thd_migrateInfo> luhya_res_get_migrate_instance_list(1:string userName);
    
    thd_hard_source luhya_res_get_server_resource(1:string serviceId,2:string hostIp);
    
    thd_MIGRATESTATE luhya_res_get_migrage_state(1:string transactionID);
    bool luhya_res_set_migrage_state(1:string transactionID, 2:thd_MIGRATESTATE state);
	string luhya_res_get_migrate_pair_node(1:string nodeIP,2:string user , 3:string imageID);
	
	i64 luhya_res_clc_run_instance(1:string user , 2:string imageID, 3:string nodeIp);
	bool luhya_res_clc_stop_instance(1:string user , 2:string imageID, 3:string nodeIp);
	i64 luhya_res_clc_restart_instance(1:string user , 2:string imageID, 3:string nodeIp);
	
	/* serviceName :  'eucalyptus-cc'   'eucalyptus-walrus'  'eucalyptus-nc'  */
	/* hostIp :       the register server ip                                  */
	/* paraName :   param , cluster name                                      */
	/* return :   0  success                                                  */
	/*            -1 no hostIp or service name                                */
	/*            -2 register cc/nc no cluster name                           */
	/*            -3 no such servive name                                     */
	/*            -4 register is error                                        */
	/*            -5 the cluster is not exist                                 */
	i64 luhya_res_clc_register_service(1:string serviceName,2:string hostIp,3:string paraName);
	
	/* serviceName :  'eucalyptus-cc'   'eucalyptus-walrus'  'eucalyptus-nc'  */
	/* parameter  :  if serviceName is eucalyptus-cc,this is clusterName ,else this is host IP */
	/* return     :   0   success                                              */
	/*                -1  serviceName or parameter is null                     */
	/*                -2  no such servive name                                 */
	/*                -3  deregister is error                                  */
	i64 luhya_res_clc_deregister_service(1:string serviceName,2:string parameter);
	
	
	/* requestIp  : the client used machine , if is None , get remote node clientData */
	list<thd_client_info> luhya_clc_get_client_data(1:string user,2:string requestIp);
	
	/* user       :   the user                                                 */
    /* imageID    :   the image of run instance                                */
    /* return     :   0   :  success                                           */
    /*                -1  :  the resource can not to run this instance         */
	/*                -2  :  in run instance is error                          */
	/*                -5  :  resoval                                           */
	/*                -6  :  resoval                                           */
	/*                -7  :  the input clientData is error                     */
	/*                -8  :  assign node is not exisit                         */
    /*                -9  :  can't dispatch cluster                            */
	/*                -10 :  can't dispatch node                               */
	i64 luhya_clc_start_vm(1:thd_client_info clientData );		
	bool luhya_clc_stop_vm(1:thd_client_info clientData );
	bool luhya_res_transmit_transcation(1:thd_transmit_data transmitData);	
	
	bool luhya_res_transmit_source(1:string IP, 2:thd_hard_source hdSource);
    bool luhya_res_heart_beat(1:string ip,2:string name);
    bool luhya_res_nc_heart_beat_dead(1:string ncIp, 2:i64 serviceID);
	
		
	bool luhya_res_delimg_update_global(1:string imageId);
	bool luhya_res_delvm_update_global(1:string vmConfigId);
	bool luhya_res_updateimg_update_global(1:thd_ImageInfo imageInfo);
	bool luhya_res_updatevm_update_global(1:thd_vmConfig vmconfig);
	bool luhya_res_addimg_update_global(1:thd_ImageInfo imageInfo);
	bool luhya_res_addvm_update_global(1:thd_vmConfig vmconfig);	
	
	thd_service_list luhya_res_get_resource_by_ip(1:string hostIp);
    bool luhya_res_add_sevice_resource(1:string hostIp,2:thd_SERVICE_TYPE serviceId);
    bool luhya_res_is_online();	
    
    bool luhya_res_is_vmconfig_used(1:string vmconfig_id);
    bool luhya_res_set_log_level(1:string str_level);
    string luhya_res_dump_clc_data(1:string strData);
}

service walrusApi{
	i64 luhya_res_getImageLength(1:string imageID );
	bool luhya_res_deleteImageFile(1:string imageID);
	i64 luhya_res_getFreeDisk();
	
	/* get the iso file list */
	list<thd_file> luhya_res_get_iso_list();
	
	/* delete iso file*/
	bool luhya_res_delete_iso_list(1:list<string> isoList);
	
	
	/* get the p2v/v2v file list */
	list<thd_file> luhya_res_get_p2v_list();
	
	i64 luhya_res_get_file_length(1:string fileName);
	thd_hard_source luhya_res_walrus_get_current_resource();
	bool  luhya_res_walrus_is_service_start();
	bool  luhya_res_walrus_start_service();
	bool  luhya_res_walrus_stop_service();
    bool  luhya_res_create_dir(1:string imagePath);
}

service clusterApi{
	list<thd_instance_info> luhya_res_getInstanceByNode(1:string nodeIp);
	bool  luhya_res_is_service_start();
	bool  luhya_res_start_service();
	bool  luhya_res_stop_service();
	thd_hard_source luhya_res_get_current_resource();
    
	i64  luhya_res_add_node(1:string nodeIp);
    
	bool luhya_res_run_instance_transaction_list(1:string nodeIp,2:list<thd_eucaTransaction> transAllList);
    bool luhya_res_get_node_hw_resource(1:string ncIp,2:thd_hard_source hdSource);
	bool luhya_res_nc_heart_beat(1:string ncIp);	
    bool luhya_res_init_nc_global_info(1:string nodeIp);
    /* to run instance, return the node ip */
    thd_run_instance_ret luhya_res_start_vm(thd_client_info clientInfo);    
}

service nodeApi{
    
	bool luhya_res_isImageDownloading(1:string imageID , 2:i64 imgLen);
	
	/*   function:     create a instance and run                      */ 
	/*   return value:                                                */
	/*                 -6:  can't create image from iso               */
	/*                 -7:  can't create image from  p2v/v2v file     */
	i64 luhya_res_runInstanceByBaseImage(1:string transactionID );
	
	string luhya_res_createMakeImageTransaction(1:string imageID , 2:i64 imageLen ,3:string user);	
	bool luhya_res_deleteMakeImageTransaction(1:string transactionID );
	thd_Transaction luhya_res_getTransactionStatusById(1:string transactionID);
	list<thd_Transaction> luhya_res_getAllTransaction();
	bool luhya_res_stopProduceImage(1:string transactionID);
	i64 luhya_res_submitImage(1:string transactionID);
	bool luhya_res_setNewImageInfo(1:string transactionID,2:thd_ImageInfo newImageInfo);
	
	/*create run instance transaction */	
	string euca_res_create_run_instance_transaction(1:string imageID , 2:i64 imageLen ,3:string user ,4:string vmconfigID);
	/* get the run instance transaction by transactionId */
	thd_eucaTransaction euca_res_get_transaction_by_id(1:string transactionID);
	/* delete the run instance transaction */
	bool euca_res_delete_run_instance_transaction(1:string transactionID);
	
	/*  function : run instance , to replace the eucalyptus run instance                       */
	/*    para:    string       transactionID        the ID of run instance transaction        */
	/*    return   i64           0   :     success                                             */
	/*                          -1   :     the resource can run this instance                  */
	/*                          -2   :     in run instance is error                            */
	/*                          -5   :     the vm config is not set                            */
	i64 euca_res_runInstance(1:string transactionID );
        bool luhya_res_stop_instance(1:string user,2:string image_id);

	/* get the list of run instance transaction for the user */
	list<thd_eucaTransaction> euca_get_run_instance_transaction_list(1:string userName);
	
	/* create a new transaction */
	string luhya_res_create_image_transaction(1:thd_Transaction transaction);
	
	/* set instance boot from , bootFrom: 'cdrom'      boot from cdroom   */
	/*                                    'harddisk'    boot from harddisk */	
	bool luhya_res_set_instance_boot_from(1:string transactionID, 2:string bootFrom);
	
	bool luhya_res_backup_instance(1:string userName,2:string imageID);
	bool luhya_res_stop_backup_instance(1:string userName,2:string imageID);
	i64 luhya_res_get_backup_time(1:string userName,2:string imageID);
	
	bool luhya_res_restore_instance(1:string userName,2:string imageID);
	thd_hard_source luhya_res_nc_get_current_resource();	
	bool luhya_res_nc_attach_iso(1:string isoFile , 2:string transactionID);
	bool  luhya_res_nc_is_service_start();
	bool  luhya_res_nc_start_service();
	bool  luhya_res_nc_stop_service();
	/* live migrate */
	i64 luhya_res_nc_live_migrage_domains(1:list<thd_migrateInfo> migrageLists);
	bool luhya_res_nc_add_migrage_transaction(1:thd_eucaTransaction transaction);
	
	bool luhya_res_nc_auto_migrate_receive_vms(1:list<thd_migrateInfo> migratevmLists);
	bool luhya_res_nc_is_live();
	bool luhya_res_nc_instance_is_running(1:string user, 2:string imageId);
	
	string luhya_res_nc_get_transId_by_user_image(1:string user,2:string imageId);
	i64 luhya_res_nc_reboot_instance(1:string transactionID);
	
	/* snapshot api */
	bool luhya_res_add_snapshot(1:thd_snapshot snapshotInfo);
    bool luhya_res_apply_snapshot(1:string userName, 2:string imageID, 3:i64 snapshotID);
    bool luhya_res_delete_snapshot(1:string userName, 2:string imageID, 3:i64 snapshotID);
    
    
    i64 luhya_res_start_vm(1:thd_client_info clientInfo);
    bool luhya_res_stop_vm(1:thd_client_info client_info); 
    list<thd_instance_info> luhya_res_get_instance_states(1:string userName);  
}
