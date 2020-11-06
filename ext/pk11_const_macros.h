#ifndef PK11_CONST_MACROS_INCLUDED
#define PK11_CONST_MACROS_INCLUDED

/**************************************************/
/* constant definition                            */
/**************************************************/

#define PKCS11_DEFINE_CONST(constant) \
  rb_define_const(MODULE_FOR_CONSTS, #constant, LONG2NUM(constant))

#define PKCS11_DEFINE_CONST_GROUP(group, name, value) \
  do { \
    VALUE rvalue, str, old; \
    rvalue = ULONG2NUM(value); \
    rb_define_const(MODULE_FOR_CONSTS, name, rvalue); \
    str = rb_obj_freeze(rb_str_new2(name)); \
    old = rb_hash_aref(group, rvalue); \
    if (!NIL_P(old)) rb_warning("%s is equal to %s", RSTRING_PTR(old), name); \
    rb_hash_aset(group, rvalue, str); \
    RB_GC_GUARD(str); \
  } while(0)

#define PKCS11_DEFINE_OBJECT_CLASS(constant) \
  PKCS11_DEFINE_CONST_GROUP(vOBJECT_CLASSES, #constant, constant)
#define PKCS11_DEFINE_ATTRIBUTE(constant) \
  PKCS11_DEFINE_CONST_GROUP(vATTRIBUTES, #constant, constant)
#define PKCS11_DEFINE_MECHANISM(constant) \
  PKCS11_DEFINE_CONST_GROUP(vMECHANISMS, #constant, constant)
#define PKCS11_DEFINE_RETURN_VALUE(constant) \
  do { \
    VALUE eError = rb_define_class_under(MODULE_FOR_CONSTS, #constant, BASECLASS_FOR_ERRORS); \
    VALUE rvalue = ULONG2NUM(constant); \
    VALUE old = rb_hash_aref(vRETURN_VALUES, rvalue); \
    if (!NIL_P(old)) rb_warning("%s is equal to %s", RSTRING_PTR(old), #constant); \
    rb_hash_aset(vRETURN_VALUES, rvalue, eError); \
  } while(0)


#endif
