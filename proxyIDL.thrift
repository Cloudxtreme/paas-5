namespace cpp CloudbotProxy
namespace py CloudbotProxy
namespace c_glib CloudbotProxy
namespace php CloudbotProxy

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
	list<thd_ImageInfo> luhya_reg_getImageList();
	string luhya_reg_getWalrusIp();
    string luhya_reg_getWalrusPort();
	list<string> luhya_reg_getCategoryList ();

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
    thd_ImageInfo luhya_reg_getImageInfo(1:string imageId);   
    thd_NodeInfo luhya_reg_get_nodeinfo_by_nodeIp(1:string nodeIp);
    thd_ClusterInfo luhya_reg_get_clusterinfo_by_cluster(1:string clusterName);

    bool luhya_reg_is_admin(1:string userName);
   
    /* live migragte */
    list<thd_nodeMigrateInfo> luhya_reg_get_node_migrate_list();
    

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
    
    bool luhya_reg_init_node_info(1:thd_NodeInfo nodeInfo);    
    string luhya_reg_get_ins_report_intv();
    bool luhya_reg_is_registered(1:thd_SERVICE_TYPE servID,2:string hostIp);
    i64 luhya_reg_get_max_private_instances(1:string user);
    
    bool luhya_reg_is_online();
    list<thd_DomainInfo> luhya_reg_get_all_domains();
}

service clcApi{
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
    bool luhya_res_set_log_level(1:string str_level);       
}
