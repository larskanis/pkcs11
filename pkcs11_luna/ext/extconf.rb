require "mkmf"
require "rubygems"

inc, lib = dir_config('luna-dir', '/usr/safenet/lunaclient/samples')
puts "using Luna Client include:#{inc}"


find_header('pk11_struct_macros.h')
find_header('pk11_const_macros.h')

have_func("rb_thread_call_without_gvl")
have_func("rb_str_set_len")

create_makefile("pkcs11_luna_ext");
