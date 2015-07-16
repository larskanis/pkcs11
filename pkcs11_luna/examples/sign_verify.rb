require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11

#This example performs a digest on some data and proceeds to sign and verify the data 
#with the signature

pkcs11 = Luna::Library.new

def destroy_object(session, label)
  session.find_objects(:LABEL=>label) do |obj|
    puts "Destroying object: #{obj.to_i}"
    obj.destroy
  end
end

def get_data
  data = ""
  (0..2048).each do |i|
    data << (i%26+65).chr
  end
  data
end

slot = Slot.new(pkcs11, SamplesConfig::SLOT)
session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
session.login(:USER, SamplesConfig::PIN)

pub_label = "Ruby RSA public key"
priv_label = "Ruby RSA private key"
destroy_object(session, pub_label)
destroy_object(session, priv_label)
    
pub_attr = {:ENCRYPT=>true, :VERIFY=>true, :MODULUS_BITS=>2048, 
  :TOKEN=>true, :WRAP=>true, :LABEL=>pub_label}
priv_attr = {:DECRYPT=>true, :SIGN=>true, :SENSITIVE=>true, :PRIVATE=>true, :TOKEN=>true, 
  :UNWRAP=>true, :LABEL=>pub_label}
    
pub_key, priv_key = session.generate_key_pair(:RSA_FIPS_186_3_PRIME_KEY_PAIR_GEN, pub_attr, priv_attr)  
  
data = get_data

signature = session.sign(:SHA256_RSA_PKCS, priv_key, data)
puts "Signature: " + signature  .bytes.map { |b| sprintf("%02X",b) }.join + " (#{signature.size})"

session.verify(:SHA256_RSA_PKCS, pub_key, signature, data)

puts "The signature was verified successfully"

session.logout
session.close
pkcs11.close


  