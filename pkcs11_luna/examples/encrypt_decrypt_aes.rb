require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11  

#This example generates an AES key and uses it to encrypt and decrypt a message

pkcs11 = Luna::Library.new

KEY_LABEL = "Ruby AES Key"

slot = Slot.new(pkcs11, SamplesConfig::SLOT)
session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
session.login(:USER, SamplesConfig::PIN)

session.find_objects(:LABEL=>KEY_LABEL) do |obj|
  puts "Destroying object: #{obj.to_i}"
  obj.destroy
end

key = session.generate_key(:AES_KEY_GEN,
  :CLASS=>CKO_SECRET_KEY, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
  :TOKEN=>true, :VALUE_LEN=>32, :LABEL=>KEY_LABEL)
  
puts "Generated AES key: (#{key[:LABEL]}, #{key.to_i})"

iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
mechanism = {:AES_CBC_PAD=>iv}
cryptogram = ""
cryptogram = session.encrypt(mechanism, key, "Can you read this?")
  
puts "Encrypted: " + cryptogram.bytes.map { |b| sprintf("%02X",b) }.join

decrypted = session.decrypt(mechanism, key, cryptogram)

puts "Decrypted: " + decrypted

session.logout
session.close
pkcs11.close
  