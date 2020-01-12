require "mkmf"
require "rubygems"

inc, lib = dir_config('luna-dir', '/usr/safenet/lunaclient/samples')
puts "using Luna Client include:#{inc}"

require_relative "generate_luna_constants"
require_relative "generate_luna_structs"

header_files = [File.join(inc, "RSA/pkcs11t.h"), File.join(inc, "cryptoki_v2.h")]

args = ["--const", "pk11l_const_def.inc", *header_files]
puts "running const parser with: #{args.join(" ")}"
PKCS11::Luna::ConstantParser.run(args)

args = ["--def", "pk11l_struct_def.inc", "--impl", "pk11l_struct_impl.inc", "--doc", "pk11l_struct.doc", *header_files]
puts "running struct parser with: #{args.join(" ")}"
PKCS11::Luna::StructParser.run(args)

find_header('pk11_struct_macros.h')
find_header('pk11_const_macros.h')

create_makefile("pkcs11_luna_ext");
