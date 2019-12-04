#include <ruby.h>
#include <ruby/thread.h>


#if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
  #define _WINDOWS
  #define OS_WIN32
  #define compile_for_windows
#else
  #define OS_LINUX
#endif


#if defined(compile_for_windows)
  #include <winbase.h> /* for LoadLibrary() */
#else
  #include <dlfcn.h>
#endif


///////////////////////////////////////

static VALUE mPKCS11;
static VALUE cPKCS11;
static VALUE mLuna;
static VALUE eLunaError;
static VALUE cLunaCStruct;
static VALUE cPkcs11CStruct;

static VALUE cCK_C_INITIALIZE_ARGS;
static VALUE aCK_C_INITIALIZE_ARGS_members;
static VALUE cCK_INFO;
static VALUE aCK_INFO_members;
static VALUE cCK_TOKEN_INFO;
static VALUE aCK_TOKEN_INFO_members;
static VALUE cCK_SLOT_INFO;
static VALUE aCK_SLOT_INFO_members;
static VALUE cCK_MECHANISM_INFO;
static VALUE aCK_MECHANISM_INFO_members;
static VALUE cCK_SESSION_INFO;
static VALUE aCK_SESSION_INFO_members;
static VALUE cCK_MECHANISM;

static VALUE vOBJECT_CLASSES;
static VALUE vATTRIBUTES;
static VALUE vMECHANISMS;
static VALUE vRETURN_VALUES;

#define MODULE_FOR_STRUCTS mLuna
#define MODULE_FOR_CONSTS mLuna
#define BASECLASS_FOR_ERRORS eLunaError
#define BASECLASS_FOR_STRUCTS cLunaCStruct

#define PKCS11_DEFINE_METHOD(name, args) \
  rb_define_method(cPKCS11, #name, pkcs11_luna_##name, args);
  
#define GetFunction(obj, name, sval) \
{ \
  pkcs11_luna_ctx *ctx; \
  Data_Get_Struct(obj, pkcs11_luna_ctx, ctx); \
  if (!ctx->sfnt_functions) rb_raise(eLunaError, "no function list"); \
  sval = (CK_##name)ctx->sfnt_functions->name; \
  if (!sval) rb_raise(eLunaError, #name " is not supported."); \
}

#define CallFunction(name, func, rv, ...) \
{ \
  struct tbr_##name##_params params = { \
    func, {__VA_ARGS__}, CKR_FUNCTION_FAILED \
  }; \
  rb_thread_call_without_gvl(tbf_##name, &params, RUBY_UBF_PROCESS, NULL); \
  rv = params.retval; \
}

#include "cryptoki_v2.h"

#include "pk11_struct_macros.h"
#include "pk11_const_macros.h"
#include "pk11_version.h"

#include "pk11l_struct_impl.inc"

typedef struct {
  void *module;
  CK_FUNCTION_LIST_PTR functions;
  CK_SFNT_CA_FUNCTION_LIST_PTR sfnt_functions;
} pkcs11_luna_ctx;

static void
pkcs11_luna_raise(VALUE self, CK_RV rv)
{
  rb_funcall(self, rb_intern("vendor_raise_on_return_value"), 1, ULONG2NUM(rv));
  rb_raise(eLunaError, "method vendor_raise_on_return_value should never return");
}

struct tbr_CA_GetFunctionList_params {
  CK_CA_GetFunctionList func;
  struct { CK_SFNT_CA_FUNCTION_LIST_PTR_PTR ppSfntFunctionList; } params;
  CK_RV retval;
};

void * tbf_CA_GetFunctionList( void *data ){
  struct tbr_CA_GetFunctionList_params *p = (struct tbr_CA_GetFunctionList_params*)data;
  p->retval = p->func( p->params.ppSfntFunctionList );
  return NULL;
}

/*struct tbr_CA_SetApplicationID_params {
  CK_CA_SetApplicationID func;
  struct { CK_ULONG major; CK_ULONG minor; } params;l
  CK_RV retval;
};

void * tbf_CA_SetApplicationID( void *data ){
  struct tbr_CA_SetApplicationID_params *p = (struct tbr_CA_SetApplicationID_params*)data;
  p->retval = p->func( p->params.major, p->params.minor );
  return NULL;
}

struct tbr_CA_OpenApplicationID_params {
  CK_CA_OpenApplicationID func;
  struct { CK_SLOT_ID slot_id;	 CK_ULONG major; CK_ULONG minor; } params;
  CK_RV retval;
};

void * tbf_CA_OpenApplicationID( void *data ){
  struct tbr_CA_OpenApplicationID_params *p = (struct tbr_CA_OpenApplicationID_params*)data;
  p->retval = p->func( p->params.slot_id, p->params.major, p->params.minor );
  return NULL;
}

struct tbr_CA_CloseApplicationID_params {
  CK_CA_CloseApplicationID func;
  struct { CK_SLOT_ID slot_id; CK_ULONG major; CK_ULONG minor; } params;
  CK_RV retval;
};

void * tbf_CA_CloseApplicationID( void *data ){
  struct tbr_CA_CloseApplicationID_params *p = (struct tbr_CA_CloseApplicationID_params*)data;
  p->retval = p->func( p->params.slot_id, p->params.major, p->params.minor);
  return NULL;
}

struct tbr_CA_LogExternal_params {
  CK_CA_LogExternal func;
  struct { CK_SLOT_ID slot_id; CK_SESSION_HANDLE hSession; CK_CHAR_PTR pString; CK_ULONG ulLen;} params;
  CK_RV retval;
};

void * tbf_CA_LogExternal( void *data ){
  struct tbr_CA_LogExternal_params *p = (struct tbr_CA_LogExternal_params*)data;
  p->retval = p->func( p->params.slot_id, p->params.hSession, p->params.pString, p->params.ulLen);
  return NULL;
}*/



static void
pkcs11_luna_ctx_free(pkcs11_luna_ctx *ctx)
{
  free(ctx);
}

//NOTE: Code commented out as it was decided to only support standard pkcs11 initially.l

/*static VALUE
pkcs11_luna_CA_SetApplicationID(VALUE self, VALUE major, VALUE minor)
{
  CK_CA_SetApplicationID func;
  CK_RV rv;

  GetFunction(self, CA_SetApplicationID, func);
  CallFunction(CA_SetApplicationID, func, rv, NUM2ULONG(major), NUM2ULONG(minor));
  if(rv != CKR_OK) 
  	pkcs11_luna_raise(self,rv);
  return self;
}

static VALUE
pkcs11_luna_CA_OpenApplicationID(VALUE self, VALUE slot_id, VALUE major, VALUE minor)
{
  CK_CA_OpenApplicationID func;
  CK_RV rv;

  GetFunction(self, CA_OpenApplicationID, func);
  CallFunction(CA_OpenApplicationID, func, rv, NUM2ULONG(slot_id), NUM2ULONG(major), NUM2ULONG(minor));
  if(rv != CKR_OK)
  	pkcs11_luna_raise(self,rv);
  return self;
}

static VALUE
pkcs11_luna_CA_CloseApplicationID(VALUE self, VALUE slot_id, VALUE major, VALUE minor)
{
  CK_CA_CloseApplicationID func;
  CK_RV rv;

  GetFunction(self, CA_CloseApplicationID, func);
  CallFunction(CA_CloseApplicationID, func, rv, NUM2ULONG(slot_id), NUM2ULONG(major), NUM2ULONG(minor));
  if(rv != CKR_OK)
  	pkcs11_luna_raise(self,rv);
  return self;
}*/

/*static VALUE
pkcs11_luna_CA_LogExternal(VALUE self, VALUE slot_id, VALUE session, VALUE message) {
  CK_CA_LogExternal func;
  CK_RV rv;

  GetFunction(self, CA_LogExternal, func);
  CallFunction(CA_LogExternal, func, rv, NUM2HANDLE(slot_id), NUM2HANDLE(session),
			(CK_CHAR_PTR)RSTRING_PTR(message), RSTRING_LEN(message));
  if(rv != CKR_OK) pkcs11_luna_raise(self,rv);

  return self;
}*/


/* rb_define_method(cPKCS11, "CA_GetFunctionList", pkcs11_CA_GetFunctionList, 0); */
/*
 * Obtains a pointer to the Cryptoki library's list of function pointers. The pointer
 * is stored in the {PKCS11::Library} object and used to call any Cryptoki functions.
 *
 * @see PKCS11::Library#initialize
 */
static VALUE
pkcs11_luna_CA_GetFunctionList(VALUE self)
{
  pkcs11_luna_ctx *ctx;
  CK_RV rv;
  CK_CA_GetFunctionList func;

  Data_Get_Struct(self, pkcs11_luna_ctx, ctx);
#ifdef compile_for_windows
  func = (CK_CA_GetFunctionList)GetProcAddress(ctx->module, "CA_GetFunctionList");
  if(!func){
    char error_text[999] = "GetProcAddress() error";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&error_text, sizeof(error_text), NULL);
    rb_raise(eLunaError, "%s", error_text);
  }
#else
  func = (CK_CA_GetFunctionList)dlsym(ctx->module, "CA_GetFunctionList");
  if(!func) rb_raise(eLunaError, "%sHERE", dlerror());
#endif
  CallFunction(CA_GetFunctionList, func, rv, &(ctx->sfnt_functions));
  if (rv != CKR_OK) 
   	pkcs11_luna_raise(self, rv);

  return self;
}

static VALUE
pkcs11_luna_s_alloc(VALUE self)
{
  VALUE obj;
  pkcs11_luna_ctx *ctx;
  obj = Data_Make_Struct(self, pkcs11_luna_ctx, 0, pkcs11_luna_ctx_free, ctx);
  return obj;
}

static VALUE
pkcs11_luna_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE path, init_args;

  rb_scan_args(argc, argv, "02", &path, &init_args);
  if( !NIL_P(path) ){
    rb_funcall(self, rb_intern("load_library"), 1, path);
    rb_funcall(self, rb_intern("C_GetFunctionList"), 0);
    rb_funcall(self, rb_intern("CA_GetFunctionList"), 0);
    rb_funcall2(self, rb_intern("C_Initialize"), 1, &init_args);
  }

  return self;
}

void
Init_pkcs11_luna_ext()
{
  VALUE eError;
  VALUE cLibrary;

  mPKCS11 = rb_const_get(rb_cObject, rb_intern("PKCS11"));

  /* Document-module: PKCS11::Luna
   *
   * Module to provide functionality for SafeNet's Luna HSMs  */
  mLuna = rb_define_module_under(mPKCS11, "Luna");
  
  /* Document-class: PKCS11::Luna::Library
   *
   * Derived class for Luna Library  */
  cLibrary = rb_const_get(mPKCS11, rb_intern("Library"));
  
  cPKCS11 = rb_define_class_under(mLuna, "Library", cLibrary);
  
  rb_define_alloc_func(cPKCS11, pkcs11_luna_s_alloc);
  rb_define_method(cPKCS11, "initialize", pkcs11_luna_initialize, -1);
  
  PKCS11_DEFINE_METHOD(CA_GetFunctionList, 0);
  //PKCS11_DEFINE_METHOD(CA_LogExternal, 3);
  //PKCS11_DEFINE_METHOD(CA_SetApplicationID, 2);
  //PKCS11_DEFINE_METHOD(CA_OpenApplicationID, 3);
  //PKCS11_DEFINE_METHOD(CA_CloseApplicationID, 3);
  

  /* Library version */
  rb_define_const( mLuna, "VERSION", rb_str_new2(VERSION) );

  eError = rb_const_get(mPKCS11, rb_intern("Error"));
  /* Document-class: PKCS11::Luna::Error
   *
   * Base class for all Luna specific exceptions (CKR_*)  */
  eLunaError = rb_define_class_under(mLuna, "Error", eError);

  cPkcs11CStruct = rb_const_get(mPKCS11, rb_intern("CStruct")); \
  cLunaCStruct = rb_define_class_under(mLuna, "CStruct", cPkcs11CStruct);

  #include "pk11l_struct_def.inc"

  vOBJECT_CLASSES = rb_hash_new();
  vATTRIBUTES = rb_hash_new();
  vMECHANISMS = rb_hash_new();
  vRETURN_VALUES = rb_hash_new();
  rb_define_const(mLuna, "OBJECT_CLASSES", vOBJECT_CLASSES);
  rb_define_const(mLuna, "ATTRIBUTES", vATTRIBUTES);
  rb_define_const(mLuna, "MECHANISMS", vMECHANISMS);
  rb_define_const(mLuna, "RETURN_VALUES", vRETURN_VALUES);

  #include "pk11l_const_def.inc"

  rb_obj_freeze(vOBJECT_CLASSES);
  rb_obj_freeze(vATTRIBUTES);
  rb_obj_freeze(vMECHANISMS);
  rb_obj_freeze(vRETURN_VALUES);

}
