require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')

include PKCS11

#This example gets the mechanisms list and displays each mechanism's 
#name and id

pkcs11 = Luna::Library.new

slot = Slot.new(pkcs11, SamplesConfig::SLOT)
mechanisms = slot.mechanisms

puts "Mechanisms(#{mechanisms.size}): "
mechanisms.each do |mech|
  puts "#{Luna::MECHANISMS[mech]}: #{mech}"
end

pkcs11.close