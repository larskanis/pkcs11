#include <ruby.h>

#if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
  #define _WINDOWS
#endif

#include <kmlib.h>
#include "pk11_struct_macros.h"
#include "pk11_const_macros.h"
#include "pk11_version.h"

///////////////////////////////////////

#include "pk11s_struct_impl.inc"

static VALUE mPKCS11;
static VALUE mProtectServer;
static VALUE eProtectServerError;
static VALUE cProtectServerCStruct;
static VALUE cPkcs11CStruct;

static VALUE vOBJECT_CLASSES;
static VALUE vATTRIBUTES;
static VALUE vMECHANISMS;
static VALUE vRETURN_VALUES;

#define MODULE_FOR_STRUCTS mProtectServer
#define MODULE_FOR_CONSTS mProtectServer
#define BASECLASS_FOR_ERRORS eProtectServerError
#define BASECLASS_FOR_STRUCTS cProtectServerCStruct

void
Init_pkcs11_protect_server_ext()
{
  VALUE eError;

  mPKCS11 = rb_const_get(rb_cObject, rb_intern("PKCS11"));
  mProtectServer = rb_define_module_under(mPKCS11, "ProtectServer");

  /* Library version */
  rb_define_const( mProtectServer, "VERSION", rb_str_new2(VERSION) );

  eError = rb_const_get(mPKCS11, rb_intern("Error"));
  /* Document-class: PKCS11::ProtectServer::Error
   *
   * Base class for all ProtectServer specific exceptions (CKR_*)  */
  eProtectServerError = rb_define_class_under(mProtectServer, "Error", eError);

  cPkcs11CStruct = rb_const_get(mPKCS11, rb_intern("CStruct")); \
  cProtectServerCStruct = rb_define_class_under(mProtectServer, "CStruct", cPkcs11CStruct);

  #include "pk11s_struct_def.inc"

  vOBJECT_CLASSES = rb_hash_new();
  vATTRIBUTES = rb_hash_new();
  vMECHANISMS = rb_hash_new();
  vRETURN_VALUES = rb_hash_new();
  rb_define_const(mProtectServer, "OBJECT_CLASSES", vOBJECT_CLASSES);
  rb_define_const(mProtectServer, "ATTRIBUTES", vATTRIBUTES);
  rb_define_const(mProtectServer, "MECHANISMS", vMECHANISMS);
  rb_define_const(mProtectServer, "RETURN_VALUES", vRETURN_VALUES);

  #include "pk11s_const_def.inc"

  rb_obj_freeze(vOBJECT_CLASSES);
  rb_obj_freeze(vATTRIBUTES);
  rb_obj_freeze(vMECHANISMS);
  rb_obj_freeze(vRETURN_VALUES);

}
