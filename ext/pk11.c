#include "pk11.h"

#if defined(compile_for_windows)
  #include <winbase.h> /* for LoadLibrary() */
#else
  #include <dlfcn.h>
#endif

static const char *VERSION = "0.1.1";

static ID sNEW;
static VALUE mPKCS11;
static VALUE cPKCS11;
static VALUE ePKCS11Error;

static VALUE cCK_ATTRIBUTE;
static VALUE cCK_C_INITIALIZE_ARGS;
static VALUE cCK_INFO;
static VALUE cCK_TOKEN_INFO;
static VALUE cCK_SLOT_INFO;
static VALUE cCK_MECHANISM_INFO;
static VALUE cCK_SESSION_INFO;
static VALUE cCK_MECHANISM;

#define HANDLE2NUM(n) ULONG2NUM(n)
#define NUM2HANDLE(n) PKNUM2ULONG(n)
#define PKNUM2ULONG(n) pkcs11_num2ulong(n)
#define pkcs11_new_struct(klass) rb_funcall(klass, sNEW, 0)

VALUE pkcs11_return_value_to_name(CK_RV);

static VALUE
pkcs11_num2ulong(VALUE val)
{
  if (TYPE(val) == T_BIGNUM || TYPE(val) == T_FIXNUM) {
    return NUM2ULONG(val);
  }
  return NUM2ULONG(rb_to_int(val));
}

static void
pkcs11_raise(CK_RV rv)
{
  VALUE message;
  message = pkcs11_return_value_to_name(rv);
  rb_raise(ePKCS11Error, "%s", RSTRING_PTR(message));
}

///////////////////////////////////////

typedef struct {
  void *module;
  CK_FUNCTION_LIST_PTR functions;
} pkcs11_ctx;

#define GetFunction(obj, name, sval) \
{ \
  pkcs11_ctx *ctx; \
  Data_Get_Struct(obj, pkcs11_ctx, ctx); \
  if (!ctx->functions) rb_raise(ePKCS11Error, "no function list"); \
  sval = (CK_##name)ctx->functions->name; \
  if (!sval) rb_raise(ePKCS11Error, #name " is not supported."); \
} while(0)

static void
pkcs11_ctx_unload_library(pkcs11_ctx *ctx)
{
#ifdef compile_for_windows
  if(ctx->module) FreeLibrary(ctx->module);
#else
  if(ctx->module) dlclose(ctx->module);
#endif
  ctx->module = NULL;
  ctx->functions = NULL;
}

static void
pkcs11_ctx_free(pkcs11_ctx *ctx)
{
  if(ctx->functions) ctx->functions->C_Finalize(NULL_PTR);
  pkcs11_ctx_unload_library(ctx);
  free(ctx);
}

static VALUE
pkcs11_C_Finalize(VALUE self)
{
  CK_C_Finalize func;
  CK_RV rv;
  
  GetFunction(self, C_Finalize, func);
  rv = func(NULL_PTR);
  if (rv != CKR_OK) pkcs11_raise(rv);
  
  return self;
}

static VALUE
pkcs11_unload_library(VALUE self)
{
  pkcs11_ctx *ctx;

  Data_Get_Struct(self, pkcs11_ctx, ctx);
  pkcs11_ctx_unload_library(ctx);

  return self;
}

static VALUE
pkcs11_s_alloc(VALUE self)
{
  VALUE obj;
  pkcs11_ctx *ctx;
  obj = Data_Make_Struct(self, pkcs11_ctx, 0, pkcs11_ctx_free, ctx);
  return obj;
}

static VALUE
pkcs11_library_new(int argc, VALUE *argv, VALUE self)
{
  return rb_funcall2(cPKCS11, sNEW, argc, argv);
}

static VALUE
pkcs11_load_library(VALUE self, VALUE path)
{
  const char *so_path;
  pkcs11_ctx *ctx;
  
  so_path = StringValuePtr(path);
  Data_Get_Struct(self, pkcs11_ctx, ctx);
#ifdef compile_for_windows
  if((ctx->module = LoadLibrary(so_path)) == NULL) {
    char error_text[999] = "LoadLibrary() error";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&error_text, sizeof(error_text), NULL);
    rb_raise(ePKCS11Error, error_text);
  }
#else
  if((ctx->module = dlopen(so_path, RTLD_NOW)) == NULL) {
    rb_raise(ePKCS11Error, "%s", dlerror());
  }
#endif

  return self;
}

static VALUE
pkcs11_C_GetFunctionList(VALUE self)
{
  pkcs11_ctx *ctx;
  CK_RV rv;
  CK_C_GetFunctionList func;

  Data_Get_Struct(self, pkcs11_ctx, ctx);
#ifdef compile_for_windows
  func = (CK_C_GetFunctionList)GetProcAddress(ctx->module, "C_GetFunctionList");
  if(!func){
    char error_text[999] = "GetProcAddress() error";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&error_text, sizeof(error_text), NULL);
    rb_raise(ePKCS11Error, error_text);
  }
#else
  func = (CK_C_GetFunctionList)dlsym(ctx->module, "C_GetFunctionList");
  if(!func) rb_raise(ePKCS11Error, "%s", dlerror());
#endif
  rv = func(&(ctx->functions));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_Initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE init_args;
  CK_C_Initialize func;
  CK_C_INITIALIZE_ARGS *args;
  CK_RV rv;

  rb_scan_args(argc, argv, "01", &init_args);
  if (NIL_P(init_args)) args = NULL_PTR;
  else {
    if (!rb_obj_is_kind_of(init_args, cCK_C_INITIALIZE_ARGS))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_C_INITIALIZE_ARGS");
    args = DATA_PTR(init_args);
  }
  GetFunction(self, C_Initialize, func);
  rv = func(args);
  if (rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE path, init_args;

  rb_scan_args(argc, argv, "02", &path, &init_args);
  if( !NIL_P(path) ){
    pkcs11_load_library(self, path);
    pkcs11_C_GetFunctionList(self);
    pkcs11_C_Initialize(1, &init_args, self);
  }

  return self;
}

static VALUE
pkcs11_C_GetInfo(VALUE self)
{
  CK_C_GetInfo func;
  CK_RV rv;
  VALUE info;

  GetFunction(self, C_GetInfo, func);
  info = pkcs11_new_struct(cCK_INFO);
  rv = func((CK_INFO_PTR)DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return info;
}

static VALUE
pkcs11_C_GetSlotList(VALUE self, VALUE presented)
{
  CK_ULONG ulSlotCount;
  CK_SLOT_ID_PTR pSlotList;
  CK_RV rv;
  CK_C_GetSlotList func;
  int i;
  VALUE ary = rb_ary_new();

  GetFunction(self, C_GetSlotList, func);
  rv = func(CK_FALSE, NULL_PTR, &ulSlotCount);
  if (rv != CKR_OK) pkcs11_raise(rv);
  pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
  rv = func(RTEST(presented) ? CK_TRUE : CK_FALSE, pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    free(pSlotList);
    pkcs11_raise(rv);
  }
  for (i = 0; i < ulSlotCount; i++)
    rb_ary_push(ary, HANDLE2NUM(pSlotList[i]));
  free(pSlotList);

  return ary;
}

static VALUE
pkcs11_C_GetSlotInfo(VALUE self, VALUE slot_id)
{
  CK_RV rv;
  CK_C_GetSlotInfo func;
  VALUE info;

  GetFunction(self, C_GetSlotInfo, func);
  info = pkcs11_new_struct(cCK_SLOT_INFO);
  rv = func(NUM2HANDLE(slot_id), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return info;
}

static VALUE
pkcs11_C_GetTokenInfo(VALUE self, VALUE slot_id)
{
  CK_RV rv;
  CK_C_GetTokenInfo func;
  VALUE info;

  GetFunction(self, C_GetTokenInfo, func);
  info = pkcs11_new_struct(cCK_TOKEN_INFO);
  rv = func(NUM2HANDLE(slot_id), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return info;
}

static VALUE
pkcs11_C_GetMechanismList(VALUE self, VALUE slot_id)
{
  CK_RV rv;
  CK_C_GetMechanismList func;
  CK_MECHANISM_TYPE_PTR types;
  CK_ULONG count;
  VALUE ary;
  int i;

  ary = rb_ary_new();
  GetFunction(self, C_GetMechanismList, func);
  rv = func(NUM2HANDLE(slot_id), NULL_PTR, &count);
  if (rv != CKR_OK) pkcs11_raise(rv);
  if (count == 0) return ary;

  types = (CK_MECHANISM_TYPE_PTR)malloc(sizeof(CK_MECHANISM_TYPE)*count);
  if (!types) rb_sys_fail(0);
  rv = func(NUM2HANDLE(slot_id), types, &count);
  if (rv != CKR_OK){
    free(types);
    pkcs11_raise(rv);
  }
  for (i = 0; i < count; i++)
    rb_ary_push(ary, HANDLE2NUM(*(types+i)));
  free(types);

  return ary;
}

static VALUE
pkcs11_C_GetMechanismInfo(VALUE self, VALUE slot_id, VALUE type)
{
  CK_RV rv;
  CK_C_GetMechanismInfo func;
  VALUE info;

  info = pkcs11_new_struct(cCK_MECHANISM_INFO);
  GetFunction(self, C_GetMechanismInfo, func);
  rv = func(NUM2HANDLE(slot_id), NUM2HANDLE(type), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return info;
}

static VALUE
pkcs11_C_InitToken(VALUE self, VALUE slot_id, VALUE pin, VALUE label)
{
  CK_RV rv;
  CK_C_InitToken func;

  StringValue(pin);
  StringValue(label);
  GetFunction(self, C_InitToken, func);
  rv = func(NUM2HANDLE(slot_id),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(label));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_InitPIN(VALUE self, VALUE session, VALUE pin)
{
  CK_RV rv;
  CK_C_InitPIN func;

  StringValue(pin);
  GetFunction(self, C_InitPIN, func);
  rv = func(NUM2HANDLE(session),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_OpenSession(VALUE self, VALUE slot_id, VALUE flags) 
{
  CK_C_OpenSession func;
  CK_RV rv;
  CK_SESSION_HANDLE handle;

  GetFunction(self, C_OpenSession, func);
  rv = func(NUM2HANDLE(slot_id), NUM2ULONG(flags), 0, 0, &handle);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(handle);
}

static VALUE
pkcs11_C_Login(VALUE self, VALUE session, VALUE user_type, VALUE pin)
{
  CK_C_Login func;
  CK_RV rv;

  StringValue(pin);
  GetFunction(self, C_Login, func);
  rv = func(NUM2HANDLE(session), NUM2ULONG(user_type),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_Logout(VALUE self, VALUE session)
{
  CK_C_Logout func;
  CK_RV rv;

  GetFunction(self, C_Logout, func);
  rv = func(NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_CloseSession(VALUE self, VALUE session)
{
  CK_C_CloseSession func;
  CK_RV rv;

  GetFunction(self, C_CloseSession, func);
  rv = func(NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_CloseAllSessions(VALUE self, VALUE slot_id)
{
  CK_C_CloseAllSessions func;
  CK_RV rv;

  GetFunction(self, C_CloseAllSessions, func);
  rv = func(NUM2HANDLE(slot_id));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_GetSessionInfo(VALUE self, VALUE session)
{
  CK_RV rv;
  CK_C_GetSessionInfo func;
  VALUE info;

  info = pkcs11_new_struct(cCK_SESSION_INFO);
  GetFunction(self, C_GetSessionInfo, func);
  rv = func(NUM2HANDLE(session), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return info;
}

static VALUE
pkcs11_C_GetOperationState(VALUE self, VALUE session)
{
  CK_RV rv;
  CK_C_GetOperationState func;
  VALUE state;
  CK_ULONG size;

  GetFunction(self, C_GetOperationState, func);
  rv = func(NUM2HANDLE(session), NULL_PTR, &size);
  if (rv != CKR_OK) pkcs11_raise(rv);
  state = rb_str_new(0, size);
  rv = func(NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(state), &size);
  if (rv != CKR_OK) pkcs11_raise(rv);

  return state;
}

static VALUE
pkcs11_C_SetOperationState(VALUE self, VALUE session, VALUE state, VALUE enc_key, VALUE auth_key)
{
  CK_RV rv;
  CK_C_SetOperationState func;

  StringValue(state);
  GetFunction(self, C_SetOperationState, func);
  rv = func(NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(state), RSTRING_LEN(state),
            NUM2HANDLE(state), NUM2HANDLE(auth_key));
  if (rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_SetPIN(VALUE self, VALUE session, VALUE old_pin, VALUE new_pin)
{
  CK_C_SetPIN func;
  CK_RV rv;

  StringValue(old_pin);
  StringValue(new_pin);
  GetFunction(self, C_SetPIN, func);
  rv = func(NUM2HANDLE(session), 
            (CK_UTF8CHAR_PTR)RSTRING_PTR(old_pin), RSTRING_LEN(old_pin),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(new_pin), RSTRING_LEN(new_pin));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static CK_ATTRIBUTE*
pkcs11_attr_ary2buf(VALUE template)
{
  int i;
  CK_ATTRIBUTE *tmp;

  Check_Type(template, T_ARRAY);
  tmp = (CK_ATTRIBUTE*)
    malloc(sizeof(CK_ATTRIBUTE)*RARRAY_LEN(template));
  if (!tmp) rb_sys_fail(0);
  for (i = 0; i < RARRAY_LEN(template); i++){
    VALUE attr = rb_ary_entry(template, i);
    if (!rb_obj_is_kind_of(attr, cCK_ATTRIBUTE)) {
      free(tmp);
      rb_raise(rb_eArgError, "templates must be an ary of PKCS11::CK_ATTRIBUTE");
    }
    memcpy(tmp+i, DATA_PTR(attr), sizeof(CK_ATTRIBUTE));
  }

  return tmp;
}

static VALUE
pkcs11_C_CreateObject(VALUE self, VALUE session, VALUE template)
{
  CK_C_CreateObject func;
  CK_RV rv;
  CK_ATTRIBUTE *tmp;
  CK_OBJECT_HANDLE handle;
 
  tmp = pkcs11_attr_ary2buf(template);
  GetFunction(self, C_CreateObject, func);
  rv = func(NUM2HANDLE(session), tmp, RARRAY_LEN(template), &handle);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(handle);
}

static VALUE
pkcs11_C_DestroyObject(VALUE self, VALUE session, VALUE handle)
{
  CK_C_DestroyObject func;
  CK_RV rv;

  GetFunction(self, C_DestroyObject, func);
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_GetObjectSize(VALUE self, VALUE session, VALUE handle)
{
  CK_C_GetObjectSize func;
  CK_RV rv;
  CK_ULONG size;

  GetFunction(self, C_GetObjectSize, func);
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle), &size);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return ULONG2NUM(size);
}

static VALUE
pkcs11_C_FindObjectsInit(VALUE self, VALUE session, VALUE template)
{
  CK_C_FindObjectsInit func;
  CK_RV rv;
  CK_ATTRIBUTE_PTR tmp = NULL_PTR;
  CK_ULONG tmp_size = 0;

  if (!NIL_P(template)){
    tmp = pkcs11_attr_ary2buf(template);
    tmp_size = RARRAY_LEN(template);
  }
  GetFunction(self, C_FindObjectsInit, func);
  rv = func(NUM2HANDLE(session), tmp, tmp_size);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_FindObjectsFinal(VALUE self, VALUE session)
{
  CK_C_FindObjectsFinal func;
  CK_RV rv;

  GetFunction(self, C_FindObjectsFinal, func);
  rv = func(NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_FindObjects(VALUE self, VALUE session, VALUE max_count)
{
  CK_C_FindObjects func;
  CK_RV rv;
  CK_OBJECT_HANDLE_PTR handles;
  CK_ULONG count = 0;
  VALUE ary;
  int i;

  handles = (CK_OBJECT_HANDLE_PTR)
      malloc(sizeof(CK_OBJECT_HANDLE)*NUM2ULONG(max_count));
  GetFunction(self, C_FindObjects, func);
  rv = func(NUM2HANDLE(session), handles, NUM2ULONG(max_count), &count);
  if(rv != CKR_OK){
    free(handles);
    pkcs11_raise(rv);
  }
  ary = rb_ary_new();
  for(i = 0; i < count; i++)
    rb_ary_push(ary, HANDLE2NUM(*(handles+i)));
  free(handles);

  return ary;
}

static VALUE ck_attr_s_alloc(VALUE);

static VALUE
pkcs11_C_GetAttributeValue(VALUE self, VALUE session, VALUE handle, VALUE template)
{
  CK_C_GetAttributeValue func;
  CK_RV rv;
  CK_ULONG i, template_size;
  CK_ATTRIBUTE_PTR tmp;
  VALUE ary;

  tmp = pkcs11_attr_ary2buf(template);
  template_size = RARRAY_LEN(template);
  GetFunction(self, C_GetAttributeValue, func);
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  if(rv != CKR_OK){
    free(tmp);
    pkcs11_raise(rv);
  }

  for (i = 0; i < template_size; i++){
    CK_ATTRIBUTE_PTR attr = tmp + i;
    if (attr->ulValueLen != -1)
      attr->pValue = (CK_BYTE_PTR)malloc(attr->ulValueLen);
  }
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  if(rv != CKR_OK){
    for (i = 0; i < template_size; i++){
      CK_ATTRIBUTE_PTR attr = tmp + i;
      if (attr->pValue) free(attr->pValue);
    }
    free(tmp);
    pkcs11_raise(rv);
  }
  ary = rb_ary_new();
  for (i = 0; i < template_size; i++){
    CK_ATTRIBUTE_PTR attr = tmp + i;
    if (attr->ulValueLen != -1){
      VALUE v = pkcs11_new_struct(cCK_ATTRIBUTE);
      memcpy(DATA_PTR(v), attr, sizeof(CK_ATTRIBUTE));
      rb_ary_push(ary, v);
    }
  }
  free(tmp);

  return ary;
}

static VALUE
pkcs11_C_SetAttributeValue(VALUE self, VALUE session, VALUE handle, VALUE template)
{
  CK_C_SetAttributeValue func;
  CK_RV rv;
  CK_ATTRIBUTE *tmp;
  CK_ULONG template_size;

  tmp = pkcs11_attr_ary2buf(template);
  template_size = RARRAY_LEN(template);
  GetFunction(self, C_SetAttributeValue, func);
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_SeedRandom(VALUE self, VALUE session, VALUE seed)
{
  CK_C_SeedRandom func;
  CK_RV rv;

  GetFunction(self, C_SeedRandom, func);
  rv = func(NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(seed), RSTRING_LEN(seed));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

static VALUE
pkcs11_C_GenerateRandom(VALUE self, VALUE session, VALUE size)
{
  CK_C_GenerateRandom func;
  CK_ULONG sz = NUM2ULONG(size);
  VALUE buf = rb_str_new(0, sz);
  CK_RV rv;

  GetFunction(self, C_GenerateRandom, func);
  rv = func(NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(buf), sz);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return buf;
}

static VALUE
pkcs11_C_WaitForSlotEvent(VALUE self, VALUE flags)
{
  CK_C_WaitForSlotEvent func;
  CK_RV rv;
  CK_SLOT_ID slot_id;

  GetFunction(self, C_WaitForSlotEvent, func);
  rv = func(NUM2ULONG(flags), &slot_id, NULL_PTR);
  if(rv == CKR_NO_EVENT) return Qnil;
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(slot_id);
}

///////////////////////////////////////

typedef VALUE (*init_func)
    (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef VALUE (*crypt_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef VALUE (*crypt_update_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef VALUE (*crypt_final_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef VALUE (*sign_update_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef VALUE (*verify_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef VALUE (*verify_final_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

#define common_crypt(s, d, sz, f)            common_crypt_update(s, d, sz, f)

static VALUE
common_init(VALUE session, VALUE mechanism, VALUE key, init_func func)
{
  CK_RV rv;
  CK_MECHANISM_PTR m;

  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  rv = func(NUM2HANDLE(session), m, NUM2HANDLE(key));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return Qnil;
}

static VALUE
common_crypt_update(VALUE session, VALUE data, VALUE size, crypt_update_func func)
{
  CK_RV rv;
  CK_ULONG sz = 0;
  VALUE buf;

  StringValue(data);
  if (NIL_P(size)){
    rv = func(NUM2HANDLE(session),
              (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
              NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  rv = func(NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
            (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(rv);
  rb_str_set_len(buf, sz);

  return buf;
}

static VALUE
common_crypt_final(VALUE session, VALUE size, crypt_final_func func)
{
  CK_RV rv;
  CK_ULONG sz = 0;
  VALUE buf;

  if (NIL_P(size)){
    rv = func(NUM2HANDLE(session), NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  rv = func(NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(rv);
  rb_str_set_len(buf, sz);

  return buf;
}

static VALUE
common_sign_update(VALUE session, VALUE data, sign_update_func func)
{
  CK_RV rv;

  StringValue(data);
  rv = func(NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return Qnil;
}

static VALUE
common_verify(VALUE session, VALUE data, VALUE sig, verify_func func)
{
  CK_RV rv;

  StringValue(data);
  StringValue(sig);
  rv = func(NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
            (CK_BYTE_PTR)RSTRING_PTR(sig), RSTRING_LEN(sig));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return Qnil;
}

////

static VALUE
pkcs11_C_EncryptInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_EncryptInit func;
  GetFunction(self, C_EncryptInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Encrypt(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Encrypt func;
  GetFunction(self, C_Encrypt, func);
  return common_crypt(session, data, size, func);
}

static VALUE
pkcs11_C_EncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_EncryptUpdate func;
  GetFunction(self, C_EncryptUpdate, func);
  return common_crypt_update(session, data, size, func);
}

static VALUE
pkcs11_C_EncryptFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_EncryptFinal func;
  GetFunction(self, C_EncryptFinal, func);
  return common_crypt_final(session, size, func);
}

static VALUE
pkcs11_C_DecryptInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_DecryptInit func;
  GetFunction(self, C_DecryptInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Decrypt(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Decrypt func;
  GetFunction(self, C_Decrypt, func);
  return common_crypt(session, data, size, func);
}

static VALUE
pkcs11_C_DecryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptUpdate func;
  GetFunction(self, C_DecryptUpdate, func);
  return common_crypt_update(session, data, size, func);
}

static VALUE
pkcs11_C_DecryptFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_DecryptFinal func;
  GetFunction(self, C_DecryptFinal, func);
  return common_crypt_final(session, size, func);
}

#define common_sign(s, d, sz, f)            common_crypt(s, d, sz, f)
#define common_sign_final(s, sz, f)         common_crypt_final(s, sz, f)
#define common_verify_update(s, d, f)       common_sign_update(s, d, f)
#define common_verify_final(s, d, f)        common_sign_update(s, d, f)
#define common_verify_recover(s, d, sz, f)  common_sign(s, d, sz, f)

static VALUE
pkcs11_C_SignInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_SignInit func;
  GetFunction(self, C_SignInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Sign(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Sign func;
  GetFunction(self, C_Sign, func);
  return common_sign(session, data, size, func);
}

static VALUE
pkcs11_C_SignUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_SignUpdate func;
  GetFunction(self, C_SignUpdate, func);
  common_sign_update(session, data, func);
  return self;
}

static VALUE
pkcs11_C_SignFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_SignFinal func;
  GetFunction(self, C_SignFinal, func);
  return common_sign_final(session, size, func);
}

static VALUE
pkcs11_C_SignRecoverInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_SignRecoverInit func;
  GetFunction(self, C_SignRecoverInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_SignRecover(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_SignRecover func;
  GetFunction(self, C_SignRecover, func);
  return common_sign(session, data, size, func);
}

static VALUE
pkcs11_C_VerifyInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_VerifyInit func;
  GetFunction(self, C_VerifyInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Verify(VALUE self, VALUE session, VALUE data, VALUE sig)
{
  CK_C_Verify func;
  GetFunction(self, C_Verify, func);
  common_verify(session, data, sig, func);
  return Qtrue;
}

static VALUE
pkcs11_C_VerifyUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_VerifyUpdate func;
  GetFunction(self, C_VerifyUpdate, func);
  common_verify_update(session, data, func);
  return self;
}

static VALUE
pkcs11_C_VerifyFinal(VALUE self, VALUE session, VALUE sig)
{
  CK_C_VerifyFinal func;
  GetFunction(self, C_VerifyFinal, func);
  common_verify_final(session, sig, func);
  return Qtrue;
}

static VALUE
pkcs11_C_VerifyRecoverInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_VerifyRecoverInit func;
  GetFunction(self, C_VerifyRecoverInit, func);
  common_init(session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_VerifyRecover(VALUE self, VALUE session, VALUE sig, VALUE size)
{
  CK_C_VerifyRecover func;
  GetFunction(self, C_VerifyRecover, func);
  common_verify_recover(session, sig, size, func);
  return Qtrue;
}

#define common_digest(s, d, sz, f)      common_crypt(s, d, sz, f)
#define common_digest_update(s, d, f)   common_sign_update(s, d, f)
#define common_digest_final(s, sz, f)   common_crypt_final(s, sz, f)

VALUE
pkcs11_C_DigestInit(VALUE self, VALUE session, VALUE mechanism)
{
  CK_C_DigestInit func;
  CK_MECHANISM_PTR m;
  CK_RV rv;

  GetFunction(self, C_DigestInit, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  rv = func(NUM2HANDLE(session), m);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

VALUE
pkcs11_C_Digest(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Digest func;
  GetFunction(self, C_Digest, func);
  return common_digest(session, data, size, func);
}

VALUE
pkcs11_C_DigestUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_DigestUpdate func;
  GetFunction(self, C_DigestUpdate, func);
  common_digest_update(session, data, func);
  return self;
}

VALUE
pkcs11_C_DigestKey(VALUE self, VALUE session, VALUE handle)
{
  CK_C_DigestKey func;
  CK_RV rv;

  GetFunction(self, C_DigestKey, func);
  rv = func(NUM2HANDLE(session), NUM2HANDLE(handle));
  if(rv != CKR_OK) pkcs11_raise(rv);

  return self;
}

VALUE
pkcs11_C_DigestFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_DigestFinal func;
  GetFunction(self, C_DigestFinal, func);
  return common_digest_final(session, size, func);
}

VALUE
pkcs11_C_DigestEncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DigestEncryptUpdate func;
  GetFunction(self, C_DigestEncryptUpdate, func);
  return common_crypt_update(session, data, size, func);
}

VALUE
pkcs11_C_DecryptDigestUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptDigestUpdate func;
  GetFunction(self, C_DecryptDigestUpdate, func);
  return common_crypt_update(session, data, size, func);
}

VALUE
pkcs11_C_SignEncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_SignEncryptUpdate func;
  GetFunction(self, C_SignEncryptUpdate, func);
  return common_crypt_update(session, data, size, func);
}

VALUE
pkcs11_C_DecryptVerifyUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptVerifyUpdate func;
  GetFunction(self, C_DecryptVerifyUpdate, func);
  return common_crypt_update(session, data, size, func);
}

VALUE
pkcs11_C_GenerateKey(VALUE self, VALUE session, VALUE mechanism, VALUE template){
  CK_C_GenerateKey func;
  CK_ATTRIBUTE_PTR tmp;
  CK_OBJECT_HANDLE handle;
  CK_MECHANISM_PTR m;
  CK_RV rv;

  GetFunction(self, C_GenerateKey, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  tmp = pkcs11_attr_ary2buf(template);
  rv = func(NUM2HANDLE(session), m, tmp, RARRAY_LEN(template), &handle);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(handle);
}

VALUE
pkcs11_C_GenerateKeyPair(VALUE self, VALUE session, VALUE mechanism, VALUE pubkey_template, VALUE privkey_template)
{
  CK_C_GenerateKeyPair func;
  CK_ATTRIBUTE_PTR pubkey_tmp, privkey_tmp;
  CK_OBJECT_HANDLE pubkey_handle, privkey_handle;
  CK_MECHANISM_PTR m;
  CK_RV rv;
  VALUE ary;

  GetFunction(self, C_GenerateKeyPair, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  pubkey_tmp = pkcs11_attr_ary2buf(pubkey_template);
  privkey_tmp = pkcs11_attr_ary2buf(privkey_template);
  rv = func(NUM2HANDLE(session), m,
            pubkey_tmp, RARRAY_LEN(pubkey_template),
            privkey_tmp, RARRAY_LEN(privkey_template),
            &pubkey_handle, &privkey_handle);
  free(pubkey_tmp);
  free(privkey_tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);
  ary = rb_ary_new();
  rb_ary_push(ary, HANDLE2NUM(pubkey_handle));
  rb_ary_push(ary, HANDLE2NUM(privkey_handle));

  return ary;
}

VALUE
pkcs11_C_WrapKey(VALUE self, VALUE session, VALUE mechanism, VALUE wrapping, VALUE wrapped, VALUE size)
{
  CK_C_WrapKey func;
  CK_MECHANISM_PTR m;
  CK_ULONG sz = 0;
  VALUE buf;
  CK_RV rv;

  GetFunction(self, C_WrapKey, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  if (NIL_P(size)){
    rv = func(NUM2HANDLE(session), m,
              NUM2HANDLE(wrapping), NUM2HANDLE(wrapped),
              (CK_BYTE_PTR)NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  rv = func(NUM2HANDLE(session), m,
            NUM2HANDLE(wrapping), NUM2HANDLE(wrapped),
            (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(rv);
  rb_str_set_len(buf, sz);

  return buf;
}

VALUE
pkcs11_C_UnwrapKey(VALUE self, VALUE session, VALUE mechanism, VALUE wrapping, VALUE wrapped, VALUE template)
{
  CK_C_UnwrapKey func;
  CK_MECHANISM_PTR m;
  CK_ATTRIBUTE_PTR tmp;
  CK_OBJECT_HANDLE h;
  CK_RV rv;

  GetFunction(self, C_UnwrapKey, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  tmp = pkcs11_attr_ary2buf(template);
  rv = func(NUM2HANDLE(session), m, NUM2HANDLE(wrapping),
            (CK_BYTE_PTR)RSTRING_PTR(wrapped), RSTRING_LEN(wrapped),
            tmp, RARRAY_LEN(template), &h);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(h);
}

VALUE
pkcs11_C_DeriveKey(VALUE self, VALUE session, VALUE mechanism, VALUE base, VALUE template)
{
  CK_C_DeriveKey func;
  CK_MECHANISM_PTR m;
  CK_ATTRIBUTE_PTR tmp;
  CK_OBJECT_HANDLE h;
  CK_RV rv;

  GetFunction(self, C_DeriveKey, func);
  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  tmp = pkcs11_attr_ary2buf(template);
  rv = func(NUM2HANDLE(session), m, NUM2HANDLE(base),
            tmp, RARRAY_LEN(template), &h);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(rv);

  return HANDLE2NUM(h);
}

///////////////////////////////////////

static void
ck_attr_free(CK_ATTRIBUTE *attr)
{
  if (attr->pValue) free(attr->pValue);
  free(attr);
}

static VALUE
ck_attr_s_alloc(VALUE self)
{
  VALUE obj;
  CK_ATTRIBUTE *attr;
  obj = Data_Make_Struct(self, CK_ATTRIBUTE, 0, ck_attr_free, attr);
  return obj;
}

static VALUE
ck_attr_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE type, value;
  CK_ATTRIBUTE *attr;

  rb_scan_args(argc, argv, "02", &type, &value);
  Data_Get_Struct(self, CK_ATTRIBUTE, attr);
  if (argc == 0) return self;
  attr->type = NUM2HANDLE(type);
  attr->pValue = NULL;
  switch(TYPE(value)){
  case T_TRUE:
    attr->pValue = (CK_BYTE_PTR)malloc(sizeof(CK_BBOOL));
    *((CK_BBOOL*)attr->pValue) = TRUE;
    attr->ulValueLen = sizeof(CK_BBOOL);
    break;
  case T_FALSE:
    attr->pValue = (CK_BYTE_PTR)malloc(sizeof(CK_BBOOL));
    *((CK_BBOOL*)attr->pValue) = FALSE;
    attr->ulValueLen = sizeof(CK_BBOOL);
    break;
  case T_NIL:
    attr->pValue = (CK_BYTE_PTR)NULL;
    attr->ulValueLen = 0;
    break;
  case T_FIXNUM:
    attr->pValue = (CK_BYTE_PTR)malloc(sizeof(CK_OBJECT_CLASS));
    *((CK_OBJECT_CLASS*)attr->pValue) = NUM2ULONG(value);
    attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    break;
  default:
    StringValue(value);
    attr->pValue = (CK_BYTE_PTR)malloc(RSTRING_LEN(value));
    memcpy(attr->pValue, RSTRING_PTR(value), RSTRING_LEN(value));
    attr->ulValueLen = RSTRING_LEN(value);
    break;
  }
  return self;
}

static VALUE
ck_attr_type(VALUE self)
{
  CK_ATTRIBUTE *attr;
  Data_Get_Struct(self, CK_ATTRIBUTE, attr);
  return ULONG2NUM(attr->type);
}

static VALUE
ck_attr_value(VALUE self)
{
  CK_ATTRIBUTE *attr;
  Data_Get_Struct(self, CK_ATTRIBUTE, attr);
  if (attr->ulValueLen == 0) return Qnil;
  switch(attr->type){
  case CKA_TOKEN:
  case CKA_PRIVATE:
  case CKA_SENSITIVE:
  case CKA_ENCRYPT:
  case CKA_DECRYPT:
  case CKA_WRAP:
  case CKA_UNWRAP:
  case CKA_SIGN:
  case CKA_SIGN_RECOVER:
  case CKA_VERIFY:
  case CKA_VERIFY_RECOVER:
  case CKA_DERIVE:
  case CKA_TRUSTED:
  case CKA_EXTRACTABLE:
  case CKA_LOCAL:
  case CKA_NEVER_EXTRACTABLE:
  case CKA_ALWAYS_SENSITIVE:
  case CKA_MODIFIABLE:
  case CKA_HAS_RESET:
  case CKA_ALWAYS_AUTHENTICATE:
  case CKA_COLOR:
  case CKA_OTP_USER_FRIENDLY_MODE:
  case CKA_WRAP_WITH_TRUSTED:
    if (attr->ulValueLen == sizeof(CK_BBOOL))
      return (*(CK_BBOOL*)(attr->pValue)) == CK_TRUE ? Qtrue : Qfalse;
    break;
  case CKA_CLASS:
  case CKA_CERTIFICATE_TYPE:
  case CKA_KEY_TYPE:
  case CKA_HW_FEATURE_TYPE:
  case CKA_BITS_PER_PIXEL:
  case CKA_CERTIFICATE_CATEGORY:
  case CKA_CHAR_COLUMNS:
  case CKA_CHAR_ROWS:
  case CKA_JAVA_MIDP_SECURITY_DOMAIN:
  case CKA_MECHANISM_TYPE:
  case CKA_OTP_SERVICE_LOGO_TYPE:
  case CKA_PIXEL_X:
  case CKA_PIXEL_Y:
  case CKA_RESOLUTION:
    if (attr->ulValueLen == sizeof(CK_ULONG))
      return ULONG2NUM(*(CK_ULONG_PTR)(attr->pValue));
    break;
  }
  return rb_str_new(attr->pValue, attr->ulValueLen);
}

///////////////////////////////////////

static VALUE
get_string(VALUE obj, off_t offset, size_t size)
{
  char *ptr = (char*)DATA_PTR(obj);
  return rb_str_new(ptr+offset, size);
}

static VALUE
set_string(VALUE obj, VALUE value, off_t offset, size_t size)
{
  char *ptr = (char*)DATA_PTR(obj);
  int len = size;
  StringValue(value);
  if (RSTRING_LEN(value) < len) len = RSTRING_LEN(value);
  memset(ptr+offset, 0, size);
  memcpy(ptr+offset, RSTRING_PTR(value), len);
  return value;
}

static VALUE
get_ulong(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  return ULONG2NUM(*(CK_ULONG_PTR)(ptr+offset));
}

static VALUE
set_ulong(VALUE obj, VALUE value, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  *(CK_ULONG_PTR)(ptr+offset) = NUM2ULONG(value);
  return value;
}

static VALUE
get_version(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  CK_VERSION_PTR v;
  char buf[64];
  v = (CK_VERSION_PTR)(ptr+offset);
  snprintf(buf, sizeof(buf), "%d.%d", v->major, v->minor);
  return rb_str_new2(buf);
}

static VALUE
set_version(VALUE obj, VALUE value, off_t offset)
{
  rb_notimplement();
  return Qnil;
}

static VALUE
get_string_ptr(VALUE obj, char *name, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  char *p = *(char**)(ptr+offset);
  if (!p) return Qnil;
  return rb_str_new2(p);
}

static VALUE
set_string_ptr(VALUE obj, VALUE value, char *name, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  rb_iv_set(obj, name, value);
  if (NIL_P(value)){
    *(CK_VOID_PTR*)(ptr+offset) = NULL_PTR;
    return value;
  }
  StringValue(value);
  value = rb_obj_freeze(rb_str_dup(value));
  *(CK_VOID_PTR*)(ptr+offset) = RSTRING_PTR(value);
  return value;
}

#define OFFSET_OF(s, f) ((off_t)((char*)&(((s*)0)->f) - (char*)0))
#define SIZE_OF(s, f) (sizeof(((s*)0)->f))

#define PKCS11_IMPLEMENT_ALLOCATOR(s) \
static VALUE s##_s_alloc(VALUE self){ \
  s *info; \
  VALUE obj = Data_Make_Struct(self, s, 0, -1, info); \
  memset(info, 0, sizeof(s)); \
  return obj; \
}

#define PKCS11_IMPLEMENT_STRING_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_string(o, OFFSET_OF(s, f), SIZE_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_string(o, v, OFFSET_OF(s, f), SIZE_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_ULONG_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_ulong(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_ulong(o, v, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_VERSION_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_version(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_version(o, v, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_STRING_PTR_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_string_ptr(o, #f, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_string_ptr(o, v, #f, OFFSET_OF(s, f)); \
}

///////////////////////////////////////

PKCS11_IMPLEMENT_ALLOCATOR(CK_C_INITIALIZE_ARGS)
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_C_INITIALIZE_ARGS, flags)
PKCS11_IMPLEMENT_STRING_PTR_ACCESSOR(CK_C_INITIALIZE_ARGS, pReserved)

PKCS11_IMPLEMENT_ALLOCATOR(CK_INFO)
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_INFO, cryptokiVersion)
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_INFO, manufacturerID)
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_INFO, flags)
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_INFO, libraryDescription)
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_INFO, libraryVersion)

PKCS11_IMPLEMENT_ALLOCATOR(CK_SLOT_INFO)
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_SLOT_INFO, slotDescription)
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_SLOT_INFO, manufacturerID)
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_SLOT_INFO, flags)
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_SLOT_INFO, hardwareVersion)
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_SLOT_INFO, firmwareVersion)

PKCS11_IMPLEMENT_ALLOCATOR(CK_TOKEN_INFO);
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_TOKEN_INFO, label);
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_TOKEN_INFO, manufacturerID);
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_TOKEN_INFO, model);
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_TOKEN_INFO, serialNumber);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, flags);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulMaxSessionCount);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulSessionCount);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulMaxRwSessionCount);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulRwSessionCount);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulMaxPinLen);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulMinPinLen);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulTotalPublicMemory);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulFreePublicMemory);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulTotalPrivateMemory);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_TOKEN_INFO, ulFreePrivateMemory);
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_TOKEN_INFO, hardwareVersion);
PKCS11_IMPLEMENT_VERSION_ACCESSOR(CK_TOKEN_INFO, firmwareVersion);
PKCS11_IMPLEMENT_STRING_ACCESSOR(CK_TOKEN_INFO, utcTime);

PKCS11_IMPLEMENT_ALLOCATOR(CK_MECHANISM_INFO);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_MECHANISM_INFO, ulMinKeySize);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_MECHANISM_INFO, ulMaxKeySize);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_MECHANISM_INFO, flags);

PKCS11_IMPLEMENT_ALLOCATOR(CK_SESSION_INFO);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_SESSION_INFO, slotID);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_SESSION_INFO, state);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_SESSION_INFO, flags);
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_SESSION_INFO, ulDeviceError);

///////////////////////////////////////

PKCS11_IMPLEMENT_ALLOCATOR(CK_MECHANISM)

static VALUE
cCK_MECHANISM_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE type, param;

  rb_scan_args(argc, argv, "02", &type, &param);
  rb_funcall(self, rb_intern("mechanism="), 1, type);
  rb_funcall(self, rb_intern("pParameter="), 1, param);

  return self;
}

PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_MECHANISM, mechanism);

static VALUE
cCK_MECHANISM_get_pParameter(VALUE self)
{
  CK_MECHANISM_PTR m = DATA_PTR(self);
  if (!m->pParameter) return Qnil;
  else return rb_str_new(m->pParameter, m->ulParameterLen);
}

static VALUE
cCK_MECHANISM_set_pParameter(VALUE self, VALUE value)
{
  CK_MECHANISM_PTR m = DATA_PTR(self);

  if (NIL_P(value)){
    m->pParameter = NULL_PTR;
    m->ulParameterLen = 0;
  }
  else{
    StringValue(value);
    value = rb_obj_freeze(rb_str_dup(value));
    m->pParameter = RSTRING_PTR(value);
    m->ulParameterLen = RSTRING_LEN(value);
  }
  rb_iv_set(self, "pParameter", value);

  return value;
}

///////////////////////////////////////

#define PKCS11_DEFINE_METHOD(name, args) \
  rb_define_method(cPKCS11, #name, pkcs11_##name, args);

#define PKCS11_DEFINE_STRUCT(s) \
  do { \
    c##s = rb_define_class_under(mPKCS11, #s, rb_cObject); \
    rb_define_alloc_func(c##s, s##_s_alloc); \
  } while(0)

#define PKCS11_DEFINE_MEMBER(s, f) \
  do { \
    rb_define_method(c##s, #f, c##s##_get_##f, 0); \
    rb_define_method(c##s, #f "=", c##s##_set_##f, 1); \
  } while(0)
  
void
Init_pkcs11_ext()
{
  mPKCS11 = rb_define_module("PKCS11");
  sNEW = rb_intern("new");
  cPKCS11 = rb_define_class_under(mPKCS11, "Library", rb_cObject);

/* Document-method: PKCS11.open
 *
 * Alias function for PKCS11::Library.new
 */
  rb_define_module_function(mPKCS11, "open", pkcs11_library_new, -1);
  
  /* Library version */
  rb_define_const( mPKCS11, "VERSION", rb_str_new2(VERSION) );
  
  ePKCS11Error = rb_define_class_under(mPKCS11, "Error", rb_eStandardError);
  rb_define_alloc_func(cPKCS11, pkcs11_s_alloc);
  rb_define_method(cPKCS11, "initialize", pkcs11_initialize, -1);

  PKCS11_DEFINE_METHOD(load_library, 1);
  PKCS11_DEFINE_METHOD(C_GetFunctionList, 0);
  PKCS11_DEFINE_METHOD(C_Initialize, -1);
  PKCS11_DEFINE_METHOD(C_GetInfo, 0);
  PKCS11_DEFINE_METHOD(C_GetSlotList, 1);
  PKCS11_DEFINE_METHOD(C_GetSlotInfo, 1);
  PKCS11_DEFINE_METHOD(C_GetTokenInfo, 1);
  PKCS11_DEFINE_METHOD(C_GetMechanismList, 1);
  PKCS11_DEFINE_METHOD(C_GetMechanismInfo, 2);
  PKCS11_DEFINE_METHOD(C_InitToken, 3);
  PKCS11_DEFINE_METHOD(C_InitPIN, 2);

  PKCS11_DEFINE_METHOD(C_OpenSession, 2);
  PKCS11_DEFINE_METHOD(C_CloseSession, 1);
  PKCS11_DEFINE_METHOD(C_CloseAllSessions, 1);
  PKCS11_DEFINE_METHOD(C_GetSessionInfo, 1);
  PKCS11_DEFINE_METHOD(C_GetOperationState, 1);
  PKCS11_DEFINE_METHOD(C_SetOperationState, 4);
  PKCS11_DEFINE_METHOD(C_Login, 3);
  PKCS11_DEFINE_METHOD(C_Logout, 1);
  PKCS11_DEFINE_METHOD(C_SetPIN, 3);

  PKCS11_DEFINE_METHOD(C_CreateObject, 2);
  PKCS11_DEFINE_METHOD(C_DestroyObject, 2);
  PKCS11_DEFINE_METHOD(C_GetObjectSize, 2);
  PKCS11_DEFINE_METHOD(C_FindObjectsInit, 2);
  PKCS11_DEFINE_METHOD(C_FindObjectsFinal, 1);
  PKCS11_DEFINE_METHOD(C_FindObjects, 2);
  PKCS11_DEFINE_METHOD(C_GetAttributeValue, 3);
  PKCS11_DEFINE_METHOD(C_SetAttributeValue, 3);

  PKCS11_DEFINE_METHOD(C_EncryptInit, 3);
  PKCS11_DEFINE_METHOD(C_Encrypt, 3);
  PKCS11_DEFINE_METHOD(C_EncryptUpdate, 3);
  PKCS11_DEFINE_METHOD(C_EncryptFinal, 2);
  PKCS11_DEFINE_METHOD(C_DecryptInit, 3);
  PKCS11_DEFINE_METHOD(C_Decrypt, 3);
  PKCS11_DEFINE_METHOD(C_DecryptUpdate, 3);
  PKCS11_DEFINE_METHOD(C_DecryptFinal, 2);
  PKCS11_DEFINE_METHOD(C_DigestInit, 2);
  PKCS11_DEFINE_METHOD(C_Digest, 3);
  PKCS11_DEFINE_METHOD(C_DigestUpdate, 2);
  PKCS11_DEFINE_METHOD(C_DigestKey, 2);
  PKCS11_DEFINE_METHOD(C_DigestFinal, 2);
  PKCS11_DEFINE_METHOD(C_SignInit, 3);
  PKCS11_DEFINE_METHOD(C_Sign, 3);
  PKCS11_DEFINE_METHOD(C_SignUpdate, 2);
  PKCS11_DEFINE_METHOD(C_SignFinal, 2);
  PKCS11_DEFINE_METHOD(C_SignRecoverInit, 3);
  PKCS11_DEFINE_METHOD(C_SignRecover, 3);
  PKCS11_DEFINE_METHOD(C_VerifyInit, 3);
  PKCS11_DEFINE_METHOD(C_Verify, 3);
  PKCS11_DEFINE_METHOD(C_VerifyUpdate, 2);
  PKCS11_DEFINE_METHOD(C_VerifyFinal, 2);
  PKCS11_DEFINE_METHOD(C_VerifyRecoverInit, 3);
  PKCS11_DEFINE_METHOD(C_VerifyRecover, 3);
  PKCS11_DEFINE_METHOD(C_DigestEncryptUpdate, 3);
  PKCS11_DEFINE_METHOD(C_DecryptDigestUpdate, 3);
  PKCS11_DEFINE_METHOD(C_SignEncryptUpdate, 3);
  PKCS11_DEFINE_METHOD(C_DecryptVerifyUpdate, 3);
  PKCS11_DEFINE_METHOD(C_GenerateKey, 3);
  PKCS11_DEFINE_METHOD(C_GenerateKeyPair, 4);
  PKCS11_DEFINE_METHOD(C_WrapKey, 5);
  PKCS11_DEFINE_METHOD(C_UnwrapKey, 5);
  PKCS11_DEFINE_METHOD(C_DeriveKey, 4);
  PKCS11_DEFINE_METHOD(C_SeedRandom, 2);
  PKCS11_DEFINE_METHOD(C_GenerateRandom, 2);

  PKCS11_DEFINE_METHOD(C_WaitForSlotEvent, 1);
  PKCS11_DEFINE_METHOD(C_Finalize, 0);
  PKCS11_DEFINE_METHOD(unload_library, 0);

  ///////////////////////////////////////

  PKCS11_DEFINE_STRUCT(CK_C_INITIALIZE_ARGS);
  PKCS11_DEFINE_MEMBER(CK_C_INITIALIZE_ARGS, flags);
  PKCS11_DEFINE_MEMBER(CK_C_INITIALIZE_ARGS, pReserved);

  cCK_ATTRIBUTE = rb_define_class_under(mPKCS11, "CK_ATTRIBUTE", rb_cObject);
  rb_define_alloc_func(cCK_ATTRIBUTE, ck_attr_s_alloc);
  rb_define_method(cCK_ATTRIBUTE, "initialize", ck_attr_initialize, -1);
  rb_define_method(cCK_ATTRIBUTE, "type", ck_attr_type, 0);
  rb_define_method(cCK_ATTRIBUTE, "value", ck_attr_value, 0);

  PKCS11_DEFINE_STRUCT(CK_INFO);
  PKCS11_DEFINE_MEMBER(CK_INFO, cryptokiVersion);
  PKCS11_DEFINE_MEMBER(CK_INFO, manufacturerID);
  PKCS11_DEFINE_MEMBER(CK_INFO, flags);
  PKCS11_DEFINE_MEMBER(CK_INFO, libraryDescription);
  PKCS11_DEFINE_MEMBER(CK_INFO, libraryVersion);

  PKCS11_DEFINE_STRUCT(CK_SLOT_INFO);
  PKCS11_DEFINE_MEMBER(CK_SLOT_INFO, slotDescription);
  PKCS11_DEFINE_MEMBER(CK_SLOT_INFO, manufacturerID);
  PKCS11_DEFINE_MEMBER(CK_SLOT_INFO, flags);
  PKCS11_DEFINE_MEMBER(CK_SLOT_INFO, hardwareVersion);
  PKCS11_DEFINE_MEMBER(CK_SLOT_INFO, firmwareVersion);

  PKCS11_DEFINE_STRUCT(CK_TOKEN_INFO);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, label);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, manufacturerID);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, model);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, serialNumber);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, flags);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulMaxSessionCount);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulSessionCount);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulMaxRwSessionCount);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulRwSessionCount);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulMaxPinLen);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulMinPinLen);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulTotalPublicMemory);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulFreePublicMemory);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulTotalPrivateMemory);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, ulFreePrivateMemory);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, hardwareVersion);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, firmwareVersion);
  PKCS11_DEFINE_MEMBER(CK_TOKEN_INFO, utcTime);

  PKCS11_DEFINE_STRUCT(CK_MECHANISM_INFO);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM_INFO, ulMinKeySize);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM_INFO, ulMaxKeySize);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM_INFO, flags);

  PKCS11_DEFINE_STRUCT(CK_SESSION_INFO);
  PKCS11_DEFINE_MEMBER(CK_SESSION_INFO, slotID);
  PKCS11_DEFINE_MEMBER(CK_SESSION_INFO, state);
  PKCS11_DEFINE_MEMBER(CK_SESSION_INFO, flags);
  PKCS11_DEFINE_MEMBER(CK_SESSION_INFO, ulDeviceError);

  PKCS11_DEFINE_STRUCT(CK_MECHANISM);
  rb_define_method(cCK_MECHANISM, "initialize", cCK_MECHANISM_initialize, -1);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM, mechanism);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM, pParameter);

  //CK_RSA_PKCS_OAEP_PARAMS
  //CK_RSA_PKCS_PSS_PARAMS
  //CK_AES_CBC_ENCRYPT_DATA_PARAMS
  //CK_AES_CTR_PARAMS
  //CK_ARIA_CBC_ENCRYPT_DATA_PARAMS
  //CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS
  //CK_CAMELLIA_CTR_PARAMS
  //CK_CMS_SIG_PARAMS
  //CK_DES_CBC_ENCRYPT_DATA_PARAMS
  //CK_ECDH1_DERIVE_PARAMS
  //CK_ECDH2_DERIVE_PARAMS
  //CK_ECMQV_DERIVE_PARAMS
  //CK_FUNCTION_LIST
  //CK_KEA_DERIVE_PARAMS
  //CK_KEY_DERIVATION_STRING_DATA
  //CK_KEY_WRAP_SET_OAEP_PARAMS
  //CK_KIP_PARAMS
  //CK_OTP_PARAM
  //CK_OTP_PARAMS
  //CK_OTP_SIGNATURE_INFO
  //CK_PBE_PARAMS
  //CK_PKCS5_PBKD2_PARAMS
  //CK_RC2_CBC_PARAMS
  //CK_RC2_MAC_GENERAL_PARAMS
  //CK_RC5_CBC_PARAMS
  //CK_RC5_MAC_GENERAL_PARAMS
  //CK_RC5_PARAMS
  //CK_SKIPJACK_PRIVATE_WRAP_PARAMS
  //CK_SKIPJACK_RELAYX_PARAMS
  //CK_SSL3_KEY_MAT_OUT
  //CK_SSL3_KEY_MAT_PARAMS
  //CK_SSL3_MASTER_KEY_DERIVE_PARAMS
  //CK_SSL3_RANDOM_DATA
  //CK_TLS_PRF_PARAMS
  //CK_WTLS_KEY_MAT_OUT
  //CK_WTLS_KEY_MAT_PARAMS
  //CK_WTLS_MASTER_KEY_DERIVE_PARAMS
  //CK_WTLS_PRF_PARAMS
  //CK_WTLS_RANDOM_DATA
  //CK_X9_42_DH1_DERIVE_PARAMS
  //CK_X9_42_DH2_DERIVE_PARAMS
  //CK_X9_42_MQV_DERIVE_PARAMS

  ///////////////////////////////////////

  Init_pkcs11_const(mPKCS11);
}
