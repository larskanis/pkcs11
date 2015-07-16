#!/usr/bin/env ruby

require 'rubygems'
require 'pkcs11_luna'
require File.join(File.dirname(__FILE__), 'config')
include PKCS11

#This example demonstrates the use of multiple threads and
#gathers some performance data.  The NUMBER_OF_THREADS and TRANSACTIONS
#constants can be modified to gather more data points.

NUMBER_OF_THREADS = 20
TRANSACTIONS = 500

KEY_LABEL = "Ruby AES Key"

def destroy_object(session, label)
  session.find_objects(:LABEL=>label) do |obj|
    puts "Destroying object: #{obj.to_i}"
    obj.destroy
  end
end

def process(slot, key)
  session = slot.open
  iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
  mechanism = {:AES_CBC_PAD=>iv}
  Thread.current[:start] = Time.now
  (1..TRANSACTIONS).each do |i|
    ciphertext = session.encrypt(mechanism, key, "Performance Test With Multiple Threads.")
  end
  Thread.current[:stop] = Time.now
  session.close
end

pkcs11 = Luna::Library.new

slot = Slot.new(pkcs11, SamplesConfig::SLOT)

session = slot.open
session.login(:USER, SamplesConfig::PIN)

destroy_object(session, KEY_LABEL)

key = session.generate_key(:AES_KEY_GEN,
  :CLASS=>CKO_SECRET_KEY, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
  :TOKEN=>true, :VALUE_LEN=>32, :LABEL=>KEY_LABEL)

threads = []

(1..NUMBER_OF_THREADS).each do |n|
  threads << Thread.new{ process(slot, key) }
end

threads.each do |t|
  t.join
end

total_time = 0
threads.each do |t|
  total_time += t[:stop] - t[:start]
end

elapsed_time = total_time / NUMBER_OF_THREADS

total = TRANSACTIONS*NUMBER_OF_THREADS
puts "Elapsed Time: " + sprintf('%.3f', elapsed_time)
puts "Total Number of Transactions: #{total}"
puts "Transactions Per Second: " + sprintf('%.3f', total/elapsed_time )

session.logout
session.close
pkcs11.close
