#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 constants and
# generator for Ruby wrapper classes.

require File.expand_path(File.join(File.dirname(__FILE__), '../../ext/generate_constants'))

module PKCS11
module Safenet
class ConstantParser < PKCS11::ConstantParser
  ConstGroups = [
    ConstTemplate.new(/#define\s+(CKM_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_MECHANISM'),
    ConstTemplate.new(/#define\s+(CKA_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_ATTRIBUTE'),
    ConstTemplate.new(/#define\s+(CKO_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_OBJECT_CLASS'),
    ConstTemplate.new(/#define\s+(CKR_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_RETURN_VALUE'),
  ]

  IgnoreConstants = %w[CKR_CERTIFICATE_NOT_YET_ACTIVE CKR_CERTIFICATE_EXPIRED]

  def start!
    File.open(options.const, "w") do |fd_const|
      options.files.each do |file_h|
        c_src = IO.read(file_h)
        ConstGroups.each do |const_group|
          c_src.scan(const_group.regexp) do
            const_name, const_value = $1, $2
            next if IgnoreConstants.include?(const_name)

            fd_const.puts "#{const_group.def}(#{const_name}); /* #{const_value} */"
          end
        end
      end
    end
  end
end
end
end


if $0==__FILE__
  PKCS11::Safenet::ConstantParser.run(ARGV)
end
