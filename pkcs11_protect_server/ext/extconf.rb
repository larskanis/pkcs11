require "mkmf"
require "rubygems"

inc, lib = dir_config('protect-server-sdk', '/opt/ETcpsdk/include', '/opt/ETcpsdk/lib')
puts "using ProtectServer-SDK include:#{inc} lib:#{lib}"

require_relative "generate_protect_server_constants"
require_relative "generate_protect_server_structs"

args = ["--const", "pk11s_const_def.inc", File.join(inc, 'ctvdef.h')]
puts "running const parser with: #{args.join(" ")}"
PKCS11::ProtectServer::ConstantParser.run(args)

args = ["--def", "pk11s_struct_def.inc", "--impl", "pk11s_struct_impl.inc", "--doc", "pk11s_struct.doc", File.join(inc, 'ctvdef.h')]
puts "running struct parser with: #{args.join(" ")}"
PKCS11::ProtectServer::StructParser.run(args)

find_header('pk11_struct_macros.h')
find_header('pk11_const_macros.h')

create_makefile("pkcs11_protect_server_ext");
