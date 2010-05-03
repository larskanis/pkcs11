require "mkmf"

basedir = File.dirname(__FILE__)
$CPPFLAGS += " -I \"#{basedir}/include\""
have_func("rb_str_set_len")
create_makefile("pkcs11");
