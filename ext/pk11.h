#ifndef RUBY_PK11_H
#define RUBY_PK11_H
#include <ruby.h>
#include <ruby/thread.h>
#include <ruby/encoding.h>

#if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
  #define compile_for_windows
#endif

void Init_pkcs11_ext();
void Init_pkcs11_const(VALUE, VALUE);

#ifdef compile_for_windows
#pragma pack(push, cryptoki, 1)
#ifdef __MINGW32_VERSION
  /* avoid warning about ignored ‘dllimport’ attribute on mingw32*/
  #define CK_IMPORT_SPEC __declspec()
#else
  #define CK_IMPORT_SPEC __declspec(dllimport)
#endif
/* Define CRYPTOKI_EXPORTS during the build of cryptoki
* libraries. Do not define it in applications.
*/
#ifdef CRYPTOKI_EXPORTS
#define CK_EXPORT_SPEC __declspec(dllexport)
#else
#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#endif
/* Ensures the calling convention for Win32 builds */
#define CK_CALL_SPEC __cdecl
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) \
returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION(returnType, name) \
returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
returnType (CK_CALL_SPEC CK_PTR name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#else

/* unix defns for pkcs11.h */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#endif

#include "pkcs11.h"
#include "otp-pkcs11.h"     /* for PKCS #11 v2.20 Amendment 1 */
#include "ct-kip.h"         /* for PKCS #11 v2.20 Amendment 2 */
#include "pkcs-11v2-20a3.h" /* for PKCS #11 v2.20 Amendment 3 */

#include "pk11_thread_funcs.h"

#endif
