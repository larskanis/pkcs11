require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11

#This example generates a public/private RSA key pair and uses the public key
#to encrypt a message and the private key to decrypt it.

pkcs11 = Luna::Library.new

def destroy_object(session, label)
  session.find_objects(:LABEL=>label) do |obj|
    puts "Destroying object: #{obj.to_i}"
    obj.destroy
  end
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
    
#RSA_PKCS_KEY_PAIR_GEN
pub_key, priv_key = session.generate_key_pair(:RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN, pub_attr, priv_attr)  
  
puts "Generated RSA public/private keys: #{pub_key[:LABEL]} (#{pub_key.to_i}), #{priv_key[:LABEL]} (#{priv_key.to_i})"

ciphertext = session.encrypt(:RSA_PKCS, pub_key, "Can you read this?")
puts "Encrypted: " + ciphertext.bytes.map { |b| sprintf("%02X",b) }.join

decrypted = session.decrypt(:RSA_PKCS, priv_key, ciphertext)

puts "Decrypted: " + decrypted

session.logout
session.close
pkcs11.close
  