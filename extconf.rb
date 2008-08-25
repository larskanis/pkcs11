require "mkmf"

$CPPFLAGS += " -I./include"
have_func("rb_str_set_len")
create_makefile("pkcs11");
