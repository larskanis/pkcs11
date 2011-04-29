require "mkmf"
require "rubygems"

inc, lib = dir_config('safenet-sdk', '/opt/ETcpsdk/include', '/opt/ETcpsdk/lib')
puts "using Safenet-SDK include:#{inc} lib:#{lib}"

# inc, lib = dir_config('ruby-pkcs11')
# inc ||= Gem.required_location('pkcs11', '../ext')
# puts "using ruby-pkcs11 include:#{inc} lib:#{lib}"
# raise "path to ruby-pkcs11/ext could not be found (use --with-ruby-pkcs11-include=my_path)" unless inc
# $INCFLAGS << " -I"+inc

find_header('pk11_struct_macros.h')
find_header('pk11_const_macros.h')

create_makefile("pkcs11_safenet_ext");
