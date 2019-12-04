require "mkmf"

basedir = File.dirname(__FILE__)
$CPPFLAGS += " -I \"#{basedir}/include\""
create_makefile("pkcs11_ext");
