
import testOpenLdap

clcip = testOpenLdap.get_clc_ip()
print "clcip is: "+clcip

certcode = testOpenLdap.get_certificate_Code('admin')
print "certificate Code is: "+certcode
hostip,port = testOpenLdap.get_walrus_info()
print "walrus ip is: "+hostip+" post is: "+port
loca = testOpenLdap.get_image_location('emi-C8E31077')
print loca
