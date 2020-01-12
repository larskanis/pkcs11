#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 constants and
# generator for Ruby wrapper classes.

require 'optparse'

module PKCS11
class ConstantParser

  attr_accessor :options

  def self.run(argv)
    s = self.new
    options = Struct.new(:verbose, :const, :files).new
    OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options] <header-file.h>*"

      opts.on("-v", "--[no-]verbose", "Run verbosely", &options.method(:verbose=))
      opts.on("--const FILE", "Write const implementations to this file", &options.method(:const=))
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
    end.parse!(argv)
    options.files = argv
    s.options = options
    s.start!
  end
  
  ConstTemplate = Struct.new :regexp, :def
  ConstGroups = [
    ConstTemplate.new(/#define\s+(CKM_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_MECHANISM'),
    ConstTemplate.new(/#define\s+(CKA_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_ATTRIBUTE'),
    ConstTemplate.new(/#define\s+(CKO_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_OBJECT_CLASS'),
    ConstTemplate.new(/#define\s+(CKR_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_RETURN_VALUE'),
  ]

  def start!
    File.open(options.const, "w") do |fd_const|
      options.files.each do |file_h|
        c_src = IO.read(file_h)
        ConstGroups.each do |const_group|
          c_src.scan(const_group.regexp) do
            const_name, const_value = $1, $2
            
            fd_const.puts "#{const_group.def}(#{const_name}); /* #{const_value} */"
          end
        end
      end
    end
  end
end
end

if $0==__FILE__
  PKCS11::ConstantParser.run(ARGV)
end
