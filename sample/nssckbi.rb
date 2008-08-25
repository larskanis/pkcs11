require "pkcs11"
require "openssl"

NSSCKBI_LIBS = [
  "/usr/lib64/libnssckbi.so",
  "/usr/lib/libnssckbi.so",
  "/usr/lib64/xulrunner/libnssckbi.so",
  "/usr/lib/xulrunner/libnssckbi.so",
  "/usr/local/lib64/xulrunner/libnssckbi.so",
  "/usr/local/lib/xulrunner/libnssckbi.so",
]
nssckbi = ARGV[0] || NSSCKBI_LIBS.find{|path| File.exist?(path) }

pkcs11 = PKCS11.new(nssckbi)
slot = pkcs11.C_GetSlotList(true).first
session = pkcs11.C_OpenSession(slot, PKCS11::CKF_SERIAL_SESSION)

pkcs11.C_FindObjectsInit(session, [
  PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_CLASS, PKCS11::CKO_CERTIFICATE)
])
handles = pkcs11.C_FindObjects(session, 1000)
pkcs11.C_FindObjectsFinal(session)

attribute_types = [
  PKCS11::CKA_CLASS,
  PKCS11::CKA_TOKEN, PKCS11::CKA_PRIVATE, PKCS11::CKA_MODIFIABLE,
  PKCS11::CKA_LABEL, PKCS11::CKA_CERTIFICATE_TYPE,
  PKCS11::CKA_SUBJECT, PKCS11::CKA_ID, PKCS11::CKA_ISSUER,
  PKCS11::CKA_SERIAL_NUMBER, PKCS11::CKA_VALUE,
]
template = attribute_types.collect{|a| PKCS11::CK_ATTRIBUTE.new(a, nil) }
handles.each do |handle|
  attributes = pkcs11.C_GetAttributeValue(session, handle, template)
  attributes.each do |attribute|
    type_name = PKCS11::ATTRIBUTES[attribute.type]
    case attribute.type
    when PKCS11::CKA_LABEL
      p [type_name, attribute.value]
    when PKCS11::CKA_SUBJECT, PKCS11::CKA_ISSUER
      p [type_name, OpenSSL::X509::Name.new(attribute.value)]
    when PKCS11::CKA_SERIAL_NUMBER
      serial = OpenSSL::ASN1.decode(attribute.value).value rescue nil
        attribute.value.unpack("w").first
      p [type_name, serial]
    when PKCS11::CKA_VALUE
      cert = OpenSSL::X509::Certificate.new(attribute.value)
      p [cert.serial, cert.not_before, cert.not_after]
    end
  end
end
