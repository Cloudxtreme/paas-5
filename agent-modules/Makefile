# Makefile
#
#

.PHONY: build clean

INIT_DEST		=debian/cloudbot-init
#JIEDIANS_DEST	=debian/cloudbot-jieidans
#GC_DEST			=debian/cloudbot-gc
#UPDATE_DEST		=debian/cloudbot-update

CLCAPI_DEST		=debian/cloudbot-clcapi
CCAPI_DEST		=debian/cloudbot-ccapi
WALRUSAPI_DEST	=debian/cloudbot-walrusapi
NCAPI_DEST		=debian/cloudbot-ncapi
REGISTRYAPI_DEST=debian/cloudbot-registryapi

PROXYCLCAPI_DEST=debian/cloudbot-proxyclcapi
PROXYREGISTRYAPI_DEST=debian/cloudbot-proxyregistryapi

INJECTOR=tools/injector.pl
EXT_DISK=tools/disk2
CLOUDBOT_TOOL=tools/cloudbot_tools.py
DUMP_CLC=tools/luhya-admin-dump-clc.py
SET_LOGLEVEL=tools/luhya-admin-setloglevel.py

build:
	thrift --gen py $(CURDIR)/../paasIDL.thrift
	cp gen-py/CloudbotWebManagement/*     $(CURDIR)/cloudbot/interface
	thrift --gen py $(CURDIR)/../proxyIDL.thrift
	cp gen-py/CloudbotProxy/*     $(CURDIR)/cloudbot/proxyinterface
	python setup.py --command-packages=stdeb.command bdist_deb

clean:
	rm -fr $(CURDIR)/gen-py
	rm  $(CURDIR)/cloudbot/interface/*
	rm  $(CURDIR)/cloudbot/proxyinterface/*

install:
	cp deb_dist/*.deb ../
	rm -fr deb_dist
    
    #  init modules config No.00
	install -d $(INIT_DEST)/etc/apt/apt.conf.d
	install -m 0644 $(CURDIR)/debian/apt.conf $(INIT_DEST)/etc/apt/apt.conf.d/90agent
	
	install -d 	$(INIT_DEST)/etc/cloud-agent/modules
	touch 		$(INIT_DEST)/etc/cloud-agent/modules/00_init

	install -d  $(INIT_DEST)/usr/bin
	install -m 0755  $(CLOUDBOT_TOOL)  $(INIT_DEST)/usr/bin/
	install -m 0755  $(DUMP_CLC)  $(INIT_DEST)/usr/bin/
	install -m 0755  $(SET_LOGLEVEL)  $(INIT_DEST)/usr/bin/

    #  registryAPI modules config No.13
	install -d 	$(REGISTRYAPI_DEST)/etc/cloud-agent/modules
	touch 		$(REGISTRYAPI_DEST)/etc/cloud-agent/modules/13_registryAPI
    
    #  gc modules config No.20
    #	install -d 	$(GC_DEST)/etc/cloud-agent/modules
    #	touch 		$(GC_DEST)/etc/cloud-agent/modules/20_gc
    
    #  update modules config No.25
    #	install -d 	$(UPDATE_DEST)/etc/cloud-agent/modules
    #	touch 		$(UPDATE_DEST)/etc/cloud-agent/modules/25_update
    
    #  clcAPI modules config No.30
	install -d 	$(CLCAPI_DEST)/etc/cloud-agent/modules
	touch 		$(CLCAPI_DEST)/etc/cloud-agent/modules/30_clcAPI
    
    #  ccAPI modules config No.35
	install -d 	$(CCAPI_DEST)/etc/cloud-agent/modules
	touch 		$(CCAPI_DEST)/etc/cloud-agent/modules/35_ccAPI
    
    #  walrusAPI modules config No.40
	install -d 	$(WALRUSAPI_DEST)/etc/cloud-agent/modules
	touch 		$(WALRUSAPI_DEST)/etc/cloud-agent/modules/40_walrusAPI  

	install -m 0755  $(EXT_DISK)  $(WALRUSAPI_DEST)/etc/cloud-agent/modules/ 
    
    #  ncAPI modules config No.45
	install -d  $(NCAPI_DEST)/usr/bin
	install -m 0755  $(INJECTOR)  $(NCAPI_DEST)/usr/bin/

	install -d 	$(NCAPI_DEST)/etc/cloud-agent/modules
	touch 		$(NCAPI_DEST)/etc/cloud-agent/modules/45_ncAPI    
    
	#  proxyclcAPI modules config No.50
	install -d 	$(PROXYCLCAPI_DEST)/etc/cloud-agent/modules
	touch 		$(PROXYCLCAPI_DEST)/etc/cloud-agent/modules/43_proxyclcAPI    

	#  proxyclcAPI modules config No.55
	install -d 	$(PROXYREGISTRYAPI_DEST)/etc/cloud-agent/modules
	touch 		$(PROXYREGISTRYAPI_DEST)/etc/cloud-agent/modules/42_proxyregistryAPI    
