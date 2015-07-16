require "rubygems"
require "pkcs11_luna"

include PKCS11

slot_id = ARGV[0]

pkcs11 = Luna::Library.new
slot = Luna::Slot.new(pkcs11, slot_id.to_i)
session = slot.open(PKCS11::CKF_RW_SESSION | PKCS11::CKF_SERIAL_SESSION)

if session.info.state == CKS_RW_USER_FUNCTIONS
  raise "Session info state had CKS_RW_USER_FUNCTIONS when not logged in!"
end

session.close
pkcs11.close

pkcs11 = Luna::Library.new
pkcs11.set_application_id(10, 10)
slot = Luna::Slot.new(pkcs11, slot_id.to_i)
session = slot.open(PKCS11::CKF_RW_SESSION | PKCS11::CKF_SERIAL_SESSION)
if session.info.state != CKS_RW_USER_FUNCTIONS
  raise "Session info state was not CKS_RW_USER_FUNCTIONS when application id set."
end
session.close
pkcs11.close

exit(true)
