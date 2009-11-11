require "pkcs11"
require "openssl"

LIBSOFTOKEN3_SO = "libsoftokn3.so"
LIBNSS_PATHS = %w(
  /usr/lib64 /usr/lib/ /usr/lib64/nss /usr/lib/nss
)
unless so_path = ARGV.shift
  paths = LIBNSS_PATHS.collect{|path| File.join(path, LIBSOFTOKEN3_SO) }
  so_path = paths.find{|path| File.exist?(path) }
end

dir = Dir.glob(File.expand_path("~/.mozilla/firefox/*.default")).first
NSS_INIT_ARGS = [
 "configDir='#{dir}'",
 "secmod='secmod.db'",
 "flags='readOnly'",
]

args = PKCS11::CK_C_INITIALIZE_ARGS.new
args.flags = 0
args.pReserved = NSS_INIT_ARGS.join(" ")

pk11 = PKCS11.new(so_path, args)
info = pk11.C_GetInfo
p [
  info.cryptokiVersion, info.manufacturerID, info.flags,
  info.libraryDescription, info.libraryVersion
]

slots = pk11.C_GetSlotList(false)
p slots

slot = 2
sinfo = pk11.C_GetSlotInfo(slot)
p [
  sinfo.slotDescription, sinfo.manufacturerID, sinfo.flags,
  sinfo.hardwareVersion, sinfo.firmwareVersion
]
mechanisms = pk11.C_GetMechanismList(slot)
mechanisms.each do |m|
  p PKCS11::MECHANISMS[m] || m
end

flags = PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION
session = pk11.C_OpenSession(slot, flags)
p [:session, session]
pk11.C_Login(session, PKCS11::CKU_USER, "")

find_template = [
  PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_CLASS, PKCS11::CKO_CERTIFICATE),
]
p pk11.C_FindObjectsInit(session, find_template)
objs = pk11.C_FindObjects(session, 128)
objs.each do |handle|
  template = [
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_SUBJECT, nil),
  ]
  attrs = pk11.C_GetAttributeValue(session, handle, template)
  attrs.each do |attr|
    p OpenSSL::X509::Name.new(attr.value)
  end
end
objs = pk11.C_FindObjectsFinal(session)

find_template = [
  PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_CLASS, PKCS11::CKO_PRIVATE_KEY),
  PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_KEY_TYPE, PKCS11::CKK_RSA),
]
p pk11.C_FindObjectsInit(session, find_template)
objs = pk11.C_FindObjects(session, 128)
objs.each do |handle|
  template = [
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_CLASS, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_KEY_TYPE, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_ID, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_SIGN, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_SIGN_RECOVER, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_DECRYPT, nil),
    PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_EXTRACTABLE, nil),
  ]
  attrs = pk11.C_GetAttributeValue(session, handle, template)
  attrs.each do |attr|
    p [PKCS11::ATTRIBUTES[attr.type], attr.value]
  end
end
objs = pk11.C_FindObjectsFinal(session)

pk11.C_Logout(session)
pk11.C_CloseSession(session)
