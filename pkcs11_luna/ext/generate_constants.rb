#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 constants and
# generator for Ruby wrapper classes.

require File.expand_path(File.join(File.dirname(__FILE__), '../../ext/generate_constants'))

module PKCS11
module Luna
class ConstantParser < PKCS11::ConstantParser
  ConstGroups = [
    ConstTemplate.new(/#define\s+(CKM_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_MECHANISM'),
    ConstTemplate.new(/#define\s+(CKA_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_ATTRIBUTE'),
    ConstTemplate.new(/#define\s+(CKO_[A-Z_0-9]+)\s+(.+)/, 'PKCS11_DEFINE_OBJECT_CLASS'),
    ConstTemplate.new(/#define\s+(CKR_[A-Z_0-9]+)\s+([A-Za-z0-9_\(\)+ ]+)/, 'PKCS11_DEFINE_RETURN_VALUE'),
  ]
  
  ['CKD', 'CKU', 'CKF', 'CKDHP', 'CKES', 'CKMS', 'CAF', 'CKCAO', 'CKHSC'].each do |prefix|
      ConstGroups << ConstTemplate.new(/#define\s+(#{prefix}_[A-Z_0-9]+)\s+([A-Za-z0-9_]+)/, 'PKCS11_DEFINE_CONST')
  end

  IgnoreConstants = %w[]  
  
  def start!
    
    constants_hash = {}
    constants = []
    
    options.files.each do |file_h|
      c_src = IO.read(file_h)
      ConstGroups.each do |const_group|
        c_src.scan(const_group.regexp) do
          const_name, const_value = $1, $2
          next if IgnoreConstants.include?(const_name)
          constants_hash[const_name] = [const_group.def, const_value]
          constants.push(const_name)
        end
      end
    end
    
    File.open(options.const, "w") do |fd_const|
      constants.each do |const_name|
        next if constants_hash[const_name].nil?
        const_group_def = constants_hash[const_name][0]
        const_value = constants_hash[const_name][1]
        fd_const.puts "#{const_group_def}(#{const_name}); /* #{const_value} */"
        constants_hash[const_name] = nil
      end
    end
  end
end

end
end

if $0==__FILE__
  PKCS11::Luna::ConstantParser.run(ARGV)
end
