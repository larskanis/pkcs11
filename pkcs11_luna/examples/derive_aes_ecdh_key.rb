#!/usr/bin/env ruby

require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11

#This example demonstrates deriving an AES key using the ECDH public key of 
#another participant and using the keys to encrypt and decrypt data.


PUBLIC_KEY_LABEL = "'s Ruby Public EC Key"
PRIVATE_KEY_LABEL = "'s Ruby Private EC Key"
DERIVED_KEY_LABEL = "'s Ruby ECDH Derived AES Key"

def destroy_object(session, label)
  session.find_objects(:LABEL=>label) do |obj|
    puts "Destroying object: #{obj.to_i}"
    obj.destroy
  end
end

class Party
  include PKCS11
  
  attr_reader :pub_key
  attr_reader :priv_key
  
  def initialize(session, name)
    @session = session
    @name = name
    @shared_data = "SHARED DATA"
  end
  
  def generate_key()
    destroy_object(@session, @name + PUBLIC_KEY_LABEL)
    destroy_object(@session, @name + PRIVATE_KEY_LABEL)
    
    #DER encoding of OID 1.3.132.0.10 secp256k1
    curve_oid_der = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A].pack("C*")
    
    attributes_public = {:TOKEN=>true, :ENCRYPT=>true, :VERIFY=>true, :WRAP=>true,
      :EC_PARAMS=>curve_oid_der, :LABEL=>@name + PUBLIC_KEY_LABEL}
    attributes_private = {:TOKEN=>true, :DECRYPT=>true, :SIGN=>true, 
      :DERIVE=>true, :UNWRAP=>true, :SENSITIVE=>true, :LABEL=>@name + PRIVATE_KEY_LABEL}
                         
    @pub_key, @priv_key = @session.generate_key_pair(:EC_KEY_PAIR_GEN, attributes_public, attributes_private)
      
    puts "Generated Public EC key: (#{@pub_key[:LABEL]}, #{@pub_key.to_i})"
    puts "Generated Private EC key: (#{@priv_key[:LABEL]}, #{@priv_key.to_i})"
  end
  
  def derive_key(other)
    destroy_object(@session, @name + DERIVED_KEY_LABEL)
    
    ec_point = other.pub_key.attributes(:EC_POINT)[0].value
    mechanism = {:ECDH1_DERIVE=>{:kdf=>Luna::CKD_SHA512_KDF, :pSharedData=>@shared_data, :pPublicData=>ec_point}}
    
    derive_attributes = {:CLASS=>CKO_SECRET_KEY, :KEY_TYPE=>CKK_AES, :TOKEN=>true, :SENSITIVE=>true, :PRIVATE=>true,
    :ENCRYPT=>true, :DECRYPT=>true, :SIGN=>true, :VERIFY=>true, :VALUE_LEN=>32, :LABEL=>@name + DERIVED_KEY_LABEL}
    
    @derived_key = @session.derive_key(mechanism, @priv_key, derive_attributes)
    
    puts "Derived AES key: (#{@derived_key[:LABEL]}, #{@derived_key.to_i})"
  end
  
  def send_message(message)
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack("C*")
    encrypted_message = @session.encrypt({:AES_CBC_PAD=>iv}, @derived_key, message)
    hex = encrypted_message.bytes.map { |b| sprintf("%02X",b) }.join  
    puts "#{@name} sent encrypted message: #{hex}"
    return encrypted_message
  end
  
  def receive_message(encrypted_message)
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack("C*")
    decrypted_message = @session.decrypt({:AES_CBC_PAD=>iv}, @derived_key, encrypted_message)
    puts "#{@name} decrypted message: #{decrypted_message}"
    return decrypted_message
  end
    
end


pkcs11 = Luna::Library.new

slot = PKCS11::Slot.new(pkcs11, SamplesConfig::SLOT)
session = slot.open
 
session.login(:USER, SamplesConfig::PIN)

alice = Party.new(session, "Alice")
bob = Party.new(session, "Bob")
alice.generate_key()
bob.generate_key()
alice.derive_key(bob)
bob.derive_key(alice)

encrypted_message = alice.send_message("Hello Bob!")
bob.receive_message(encrypted_message)

encrypted_message = bob.send_message("Hi Alice!")
alice.receive_message(encrypted_message)


session.logout
session.close
pkcs11.close