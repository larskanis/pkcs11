#ifndef RUBY_PK11_H
#define RUBY_PK11_H
#include <ruby.h>

#if !defined(RARRAY_LEN)
# define RARRAY_LEN(ary) (RARRAY(ary)->len)
#endif
#if !defined(RSTRING_LEN)
# define RSTRING_LEN(str) (RSTRING(str)->len)
#endif
#if !defined(RSTRING_PTR)
# define RSTRING_PTR(str) (RSTRING(str)->ptr)
#endif

#ifndef HAVE_RB_STR_SET_LEN
#define rb_str_set_len(str, length) do { \
  RSTRING(str)->ptr[length] = 0; \
  RSTRING(str)->len = length; \
} while(0)
#endif

void Init_pkcs11_ext();
void Init_pkcs11_const(VALUE);

/* unix defns for pkcs11.h */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"
#include "otp-pkcs11.h"     /* for PKCS #11 v2.20 Amendment 1 */ 
#include "ct-kip.h"         /* for PKCS #11 v2.20 Amendment 2 */ 
#include "pkcs-11v2-20a3.h" /* for PKCS #11 v2.20 Amendment 3 */ 
#endif
