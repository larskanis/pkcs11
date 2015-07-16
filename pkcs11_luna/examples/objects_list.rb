require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11  

#This example obtains and displays the name and object handle
#of all objects

pkcs11 = Luna::Library.new

KEY_LABEL = "Ruby AES Key"

slot = Slot.new(pkcs11, SamplesConfig::SLOT)
session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
session.login(:USER, SamplesConfig::PIN)

session.find_objects() do |obj|
   puts "#{obj[:LABEL]}: #{obj.to_i}"
end

session.logout
session.close
pkcs11.close