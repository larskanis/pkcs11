#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 structs and
# generator for Ruby wrapper classes.

require 'rubygems'
require 'pkcs11'
require '../ext/generate_structs.rb'

module PKCS11
module Safenet
class StructParser < PKCS11::StructParser

  SIZE_CONSTANTS = {
    'CK_MANUFACTURER_SIZE' => 32,
    'CK_SERIAL_NUMBER_SIZE' => 16,
    'CK_TIME_SIZE' => 16,
    'CK_LIB_DESC_SIZE' => 32,
    'CK_SLOT_DESCRIPTION_SIZE' => 64,
    'CK_SLOT_MANUFACTURER_SIZE' => 32,
    'CK_MAX_PIN_LEN' => 32,
    'CK_TOKEN_LABEL_SIZE' => 32,
    'CK_TOKEN_MANUFACTURER_SIZE' => 32,
    'CK_TOKEN_MODEL_SIZE' => 16,
    'CK_TOKEN_SERIAL_NUMBER_SIZE' => 16,
    'CK_TOKEN_TIME_SIZE' => 16,
    'CK_MAX_PBE_IV_SIZE' =>	8,
    'CK_MAX_PAD_SIZE' => 16,
  }

  ULONG_TYPES = %w[CK_COUNT CK_SIZE CK_TIMESTAMP_FORMAT]
  ULONG_PTR_TYPES = %w[CK_COUNT_PTR]

  def struct_module
    'PKCS11::Safenet'
  end

  def array_attribute_names; %w[attributes mechanism certAttr hCert]; end

  def parse_files(files)
    structs = []
    files.each do |file_h|
      c_src = IO.read(file_h)
      c_src.scan(/struct\s+([A-Z_0-9]+)\s*\{(.*?)\}/m) do |struct|
        struct_text = $2
        struct = PKCS11::StructParser::CStruct.new( $1, [] )

        struct_text.scan(/^\s+([A-Z_0-9]+)([\*\s]+)([\w_]+)\s*(\[\s*(\w+)\s*\])?/) do |elem|
          type, name = $1, $3
          qual = SIZE_CONSTANTS[$5] || $5
          ptr = $2.include?('*')
          type = "CK_ULONG" if ULONG_TYPES.include?(type)
          type = "CK_ULONG_PTR" if ULONG_PTR_TYPES.include?(type)
          struct.attrs << Attribute.new(ptr ? type+"_PTR" : type, name, qual)
        end
        structs << struct
      end
    end
    return structs
  end

  def start!
    @structs = parse_files(options.files)
    @structs_by_name = @structs.inject({}){|sum, v| sum[v.name]=v; sum }
    @std_structs_by_name = PKCS11.constants.select{|c| PKCS11.const_get(c).respond_to?(:ancestors) && !(PKCS11.const_get(c).ancestors & [PKCS11::CStruct, PKCS11::CK_ATTRIBUTE]).empty? }.inject({}){|sum, v| sum[v]=true; sum }

    write_files
  end
end
end
end


if $0==__FILE__
  PKCS11::Safenet::StructParser.run(ARGV)
end
