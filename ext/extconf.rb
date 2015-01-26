require "mkmf"

basedir = File.dirname(__FILE__)
$CPPFLAGS += " -I \"#{basedir}/include\""
have_func("rb_str_set_len")
have_func("rb_thread_call_without_gvl")
create_makefile("pkcs11_ext");
