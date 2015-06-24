require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')

include PKCS11

#This example shows the label and token for all slots.

pkcs11 = Luna::Library.new

pkcs11.slots.each do |slot|
  info = slot.info
  puts "Slot: #{slot.to_i}"
  puts "  Label: #{info.slotDescription.strip}"
  begin
    info = slot.token_info
    puts "  Token: #{info.label}"
  rescue CKR_TOKEN_NOT_PRESENT
    puts "  Token: No token"
  end
end
  
pkcs11.close