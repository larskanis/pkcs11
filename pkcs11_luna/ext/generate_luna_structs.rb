#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 structs and
# generator for Ruby wrapper classes.

require_relative "generate_structs"
require_relative "std_structs"

module PKCS11
module Luna
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
    'CK_HA_MAX_MEMBERS' => 32
  }

  ULONG_TYPES = %w[CK_EC_DH_PRIMITIVE CK_EC_ENC_SCHEME CK_EC_MAC_SCHEME CK_KDF_PRF_ENCODING_SCHEME CK_RV]
  ULONG_PTR_TYPES = %w[]


  def struct_module
    'PKCS11::Luna'
  end

  def array_attribute_names; %w[attributes mechanism certAttr hCert]; end

  def parse_files(files)
    structs = []
    files.each do |file_h|
      c_src = File.binread(file_h)
      c_src.scan(/struct\s+([A-Z_0-9]+)\s*\{(.*?)\}\s*([A-Z_0-9]+)\s*;/m) do |struct|
        struct_text = $2
        struct = PKCS11::StructParser::CStruct.new( $3, [] )

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
    @std_structs_by_name = PKCS11_STD_STRUCTS.inject({}){|sum, v| sum[v.to_s]=true; sum }

    write_files
  end
end
end
end


if $0==__FILE__
  PKCS11::Luna::StructParser.run(ARGV)
end
