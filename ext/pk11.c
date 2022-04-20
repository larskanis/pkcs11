#include "pk11.h"
#include "pk11_struct_macros.h"
#include "pk11_version.h"

#if defined(compile_for_windows)
  #include <winbase.h> /* for LoadLibrary() */
#else
  #include <dlfcn.h>
#endif

static ID sNEW;
static VALUE mPKCS11;
static VALUE cPKCS11;
static VALUE ePKCS11Error;

static VALUE cCStruct;
static VALUE cCK_ATTRIBUTE;
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
static VALUE aCK_MECHANISM_members;

#define MODULE_FOR_STRUCTS mPKCS11
#define BASECLASS_FOR_STRUCTS cCStruct
#define pkcs11_new_struct(klass) rb_funcall(klass, sNEW, 0)

#define PKCS11_DEFINE_METHOD(name, args) \
  rb_define_method(cPKCS11, #name, pkcs11_##name, args);

VALUE pkcs11_return_value_to_class(CK_RV, VALUE);

static void
pkcs11_raise(VALUE self, CK_RV rv)
{
  rb_funcall(self, rb_intern("vendor_raise_on_return_value"), 1, ULONG2NUM(rv));
  rb_raise(ePKCS11Error, "method vendor_raise_on_return_value should never return");
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
}

#define CallFunction(name, func, rv, ...) \
{ \
  struct tbr_##name##_params params = { \
    func, {__VA_ARGS__}, CKR_FUNCTION_FAILED \
  }; \
  rb_thread_call_without_gvl(tbf_##name, &params, RUBY_UBF_PROCESS, NULL); \
  rv = params.retval; \
}

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

/* rb_define_method(cPKCS11, "C_Finalize", pkcs11_C_Finalize, 0); */
/*
 * Is called to indicate that an application is finished with the Cryptoki library.
 * @see PKCS11::Library#close
 */
static VALUE
pkcs11_C_Finalize(VALUE self)
{
  CK_C_Finalize func;
  CK_RV rv;

  GetFunction(self, C_Finalize, func);
  CallFunction(C_Finalize, func, rv, NULL_PTR);
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

/* rb_define_method(cPKCS11, "unload_library", pkcs11_unload_library, 0); */
/*
 * Unloads the Cryptoki library from process memory.
 * @see PKCS11::Library#close
 */
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

/* rb_define_method(cPKCS11, "load_library", pkcs11_load_library, 0); */
/*
 * Load a Cryptoki library into process memory.
 * @see PKCS11::Library#initialize
 */
static VALUE
pkcs11_load_library(VALUE self, VALUE path)
{
  const char *so_path;
  pkcs11_ctx *ctx;

  so_path = StringValueCStr(path);
  Data_Get_Struct(self, pkcs11_ctx, ctx);
#ifdef compile_for_windows
  if((ctx->module = LoadLibrary(so_path)) == NULL) {
    char error_text[999] = "LoadLibrary() error";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPTSTR)&error_text, sizeof(error_text), NULL);
    rb_raise(ePKCS11Error, "%s", error_text);
  }
#else
  if((ctx->module = dlopen(so_path, RTLD_NOW)) == NULL) {
    rb_raise(ePKCS11Error, "%s", dlerror());
  }
#endif

  return self;
}

/* rb_define_method(cPKCS11, "C_GetFunctionList", pkcs11_C_GetFunctionList, 0); */
/*
 * Obtains a pointer to the Cryptoki library's list of function pointers. The pointer
 * is stored in the {PKCS11::Library} object and used to call any Cryptoki functions.
 *
 * @see PKCS11::Library#initialize
 */
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
    rb_raise(ePKCS11Error, "%s", error_text);
  }
#else
  func = (CK_C_GetFunctionList)dlsym(ctx->module, "C_GetFunctionList");
  if(!func) rb_raise(ePKCS11Error, "%s", dlerror());
#endif
  CallFunction(C_GetFunctionList, func, rv, &(ctx->functions));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

/* rb_define_method(cPKCS11, "C_Initialize", pkcs11_C_Initialize, 0); */
/*
 * Initializes the Cryptoki library.
 */
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
  CallFunction(C_Initialize, func, rv, args);
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE path, init_args;

  rb_scan_args(argc, argv, "02", &path, &init_args);
  if( !NIL_P(path) ){
    rb_funcall(self, rb_intern("load_library"), 1, path);
    rb_funcall(self, rb_intern("C_GetFunctionList"), 0);
    rb_funcall2(self, rb_intern("C_Initialize"), 1, &init_args);
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
  CallFunction(C_GetInfo, func, rv, (CK_INFO_PTR)DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return info;
}

static VALUE
pkcs11_C_GetSlotList(VALUE self, VALUE presented)
{
  CK_ULONG ulSlotCount;
  CK_SLOT_ID_PTR pSlotList;
  CK_RV rv;
  CK_C_GetSlotList func;
  CK_ULONG i;
  VALUE ary = rb_ary_new();

  GetFunction(self, C_GetSlotList, func);
  CallFunction(C_GetSlotList, func, rv, CK_FALSE, NULL_PTR, &ulSlotCount);
  if (rv != CKR_OK) pkcs11_raise(self,rv);
  pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount*sizeof(CK_SLOT_ID));
  CallFunction(C_GetSlotList, func, rv, RTEST(presented) ? CK_TRUE : CK_FALSE, pSlotList, &ulSlotCount);
  if (rv != CKR_OK) {
    free(pSlotList);
    pkcs11_raise(self,rv);
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
  CallFunction(C_GetSlotInfo, func, rv, NUM2HANDLE(slot_id), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_GetTokenInfo, func, rv, NUM2HANDLE(slot_id), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

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
  CK_ULONG i;

  ary = rb_ary_new();
  GetFunction(self, C_GetMechanismList, func);
  CallFunction(C_GetMechanismList, func, rv, NUM2HANDLE(slot_id), NULL_PTR, &count);
  if (rv != CKR_OK) pkcs11_raise(self,rv);
  if (count == 0) return ary;

  types = (CK_MECHANISM_TYPE_PTR)malloc(sizeof(CK_MECHANISM_TYPE)*count);
  if (!types) rb_sys_fail(0);
  CallFunction(C_GetMechanismList, func, rv, NUM2HANDLE(slot_id), types, &count);
  if (rv != CKR_OK){
    free(types);
    pkcs11_raise(self,rv);
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
  CallFunction(C_GetMechanismInfo, func, rv, NUM2HANDLE(slot_id), NUM2HANDLE(type), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return info;
}

static VALUE
pkcs11_C_InitToken(VALUE self, VALUE slot_id, VALUE pin, VALUE label)
{
  CK_RV rv;
  CK_C_InitToken func;

  StringValue(pin);
  StringValueCStr(label);
  GetFunction(self, C_InitToken, func);
  CallFunction(C_InitToken, func, rv, NUM2HANDLE(slot_id),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(label));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_InitPIN(VALUE self, VALUE session, VALUE pin)
{
  CK_RV rv;
  CK_C_InitPIN func;

  StringValue(pin);
  GetFunction(self, C_InitPIN, func);
  CallFunction(C_InitPIN, func, rv, NUM2HANDLE(session),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_OpenSession(VALUE self, VALUE slot_id, VALUE flags)
{
  CK_C_OpenSession func;
  CK_RV rv;
  CK_SESSION_HANDLE handle;

  GetFunction(self, C_OpenSession, func);
  CallFunction(C_OpenSession, func, rv, NUM2HANDLE(slot_id), NUM2ULONG(flags), 0, 0, &handle);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return HANDLE2NUM(handle);
}

static VALUE
pkcs11_C_Login(VALUE self, VALUE session, VALUE user_type, VALUE pin)
{
  CK_C_Login func;
  CK_RV rv;

  StringValue(pin);
  GetFunction(self, C_Login, func);
  CallFunction(C_Login, func, rv, NUM2HANDLE(session), NUM2ULONG(user_type),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(pin), RSTRING_LEN(pin));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_Logout(VALUE self, VALUE session)
{
  CK_C_Logout func;
  CK_RV rv;

  GetFunction(self, C_Logout, func);
  CallFunction(C_Logout, func, rv, NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_CloseSession(VALUE self, VALUE session)
{
  CK_C_CloseSession func;
  CK_RV rv;

  GetFunction(self, C_CloseSession, func);
  CallFunction(C_CloseSession, func, rv, NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_CloseAllSessions(VALUE self, VALUE slot_id)
{
  CK_C_CloseAllSessions func;
  CK_RV rv;

  GetFunction(self, C_CloseAllSessions, func);
  CallFunction(C_CloseAllSessions, func, rv, NUM2HANDLE(slot_id));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_GetSessionInfo, func, rv, NUM2HANDLE(session), DATA_PTR(info));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_GetOperationState, func, rv, NUM2HANDLE(session), NULL_PTR, &size);
  if (rv != CKR_OK) pkcs11_raise(self,rv);
  state = rb_str_new(0, size);
  CallFunction(C_GetOperationState, func, rv, NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(state), &size);
  if (rv != CKR_OK) pkcs11_raise(self,rv);
  rb_str_set_len(state, size);

  return state;
}

static VALUE
pkcs11_C_SetOperationState(VALUE self, VALUE session, VALUE state, VALUE enc_key, VALUE auth_key)
{
  CK_RV rv;
  CK_C_SetOperationState func;

  StringValue(state);
  GetFunction(self, C_SetOperationState, func);
  CallFunction(C_SetOperationState, func, rv, NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(state), RSTRING_LEN(state),
            NUM2HANDLE(enc_key), NUM2HANDLE(auth_key));
  if (rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_SetPIN, func, rv, NUM2HANDLE(session),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(old_pin), RSTRING_LEN(old_pin),
            (CK_UTF8CHAR_PTR)RSTRING_PTR(new_pin), RSTRING_LEN(new_pin));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_CreateObject, func, rv, NUM2HANDLE(session), tmp, RARRAY_LEN(template), &handle);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return HANDLE2NUM(handle);
}

static VALUE
pkcs11_C_CopyObject(VALUE self, VALUE session, VALUE object, VALUE template)
{
  CK_C_CopyObject func;
  CK_RV rv;
  CK_ATTRIBUTE *tmp;
  CK_OBJECT_HANDLE handle;

  tmp = pkcs11_attr_ary2buf(template);
  GetFunction(self, C_CopyObject, func);
  CallFunction(C_CopyObject, func, rv, NUM2HANDLE(session), NUM2HANDLE(object), tmp, RARRAY_LEN(template), &handle);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return HANDLE2NUM(handle);
}

static VALUE
pkcs11_C_DestroyObject(VALUE self, VALUE session, VALUE handle)
{
  CK_C_DestroyObject func;
  CK_RV rv;

  GetFunction(self, C_DestroyObject, func);
  CallFunction(C_DestroyObject, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_GetObjectSize(VALUE self, VALUE session, VALUE handle)
{
  CK_C_GetObjectSize func;
  CK_RV rv;
  CK_ULONG size;

  GetFunction(self, C_GetObjectSize, func);
  CallFunction(C_GetObjectSize, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle), &size);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_FindObjectsInit, func, rv, NUM2HANDLE(session), tmp, tmp_size);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_FindObjectsFinal(VALUE self, VALUE session)
{
  CK_C_FindObjectsFinal func;
  CK_RV rv;

  GetFunction(self, C_FindObjectsFinal, func);
  CallFunction(C_FindObjectsFinal, func, rv, NUM2HANDLE(session));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CK_ULONG i;

  handles = (CK_OBJECT_HANDLE_PTR)
      malloc(sizeof(CK_OBJECT_HANDLE)*NUM2ULONG(max_count));
  GetFunction(self, C_FindObjects, func);
  CallFunction(C_FindObjects, func, rv, NUM2HANDLE(session), handles, NUM2ULONG(max_count), &count);
  if(rv != CKR_OK){
    free(handles);
    pkcs11_raise(self,rv);
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
  VALUE class_attr = rb_funcall(self, rb_intern("vendor_class_CK_ATTRIBUTE"), 0);

  tmp = pkcs11_attr_ary2buf(template);
  template_size = RARRAY_LEN(template);
  GetFunction(self, C_GetAttributeValue, func);
  CallFunction(C_GetAttributeValue, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  if(rv != CKR_OK){
    free(tmp);
    pkcs11_raise(self,rv);
  }

  for (i = 0; i < template_size; i++){
    CK_ATTRIBUTE_PTR attr = tmp + i;
    if (attr->ulValueLen != (CK_ULONG)-1)
      attr->pValue = (CK_BYTE_PTR)malloc(attr->ulValueLen);
  }
  CallFunction(C_GetAttributeValue, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  if(rv != CKR_OK){
    for (i = 0; i < template_size; i++){
      CK_ATTRIBUTE_PTR attr = tmp + i;
      if (attr->pValue) free(attr->pValue);
    }
    free(tmp);
    pkcs11_raise(self,rv);
  }
  ary = rb_ary_new();
  for (i = 0; i < template_size; i++){
    CK_ATTRIBUTE_PTR attr = tmp + i;
    if (attr->ulValueLen != (CK_ULONG)-1){
      VALUE v = pkcs11_new_struct(class_attr);
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
  CallFunction(C_SetAttributeValue, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle), tmp, template_size);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

static VALUE
pkcs11_C_SeedRandom(VALUE self, VALUE session, VALUE seed)
{
  CK_C_SeedRandom func;
  CK_RV rv;

  GetFunction(self, C_SeedRandom, func);
  CallFunction(C_SeedRandom, func, rv, NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(seed), RSTRING_LEN(seed));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_GenerateRandom, func, rv, NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(buf), sz);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return buf;
}

static VALUE
pkcs11_C_WaitForSlotEvent(VALUE self, VALUE flags)
{
  CK_C_WaitForSlotEvent func;
  CK_RV rv;
  CK_SLOT_ID slot_id;

  GetFunction(self, C_WaitForSlotEvent, func);
  CallFunction(C_WaitForSlotEvent, func, rv, NUM2ULONG(flags), &slot_id, NULL_PTR);
  if(rv == CKR_NO_EVENT) return Qnil;
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return HANDLE2NUM(slot_id);
}

///////////////////////////////////////

typedef CK_RV (*init_func)
    (CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);
typedef CK_RV (*crypt_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*crypt_update_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*crypt_final_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);
typedef CK_RV (*sign_update_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*verify_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
typedef CK_RV (*verify_final_func)
    (CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

#define common_crypt(self, s, d, sz, f)            common_crypt_update(self, s, d, sz, f)

static VALUE
common_init(VALUE self, VALUE session, VALUE mechanism, VALUE key, init_func func)
{
  CK_RV rv;
  CK_MECHANISM_PTR m;

  if (!rb_obj_is_kind_of(mechanism, cCK_MECHANISM))
      rb_raise(rb_eArgError, "2nd arg must be a PKCS11::CK_MECHANISM");
  m = DATA_PTR(mechanism);
  /* Use the function signature of any of the various C_*Init functions. */
  CallFunction(C_EncryptInit, func, rv, NUM2HANDLE(session), m, NUM2HANDLE(key));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return Qnil;
}

static VALUE
common_crypt_update(VALUE self, VALUE session, VALUE data, VALUE size, crypt_update_func func)
{
  CK_RV rv;
  CK_ULONG sz = 0;
  VALUE buf;

  StringValue(data);
  if (NIL_P(size)){
    CallFunction(C_EncryptUpdate, func, rv, NUM2HANDLE(session),
              (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
              NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(self,rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  CallFunction(C_EncryptUpdate, func, rv, NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
            (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(self,rv);
  rb_str_set_len(buf, sz);

  return buf;
}

static VALUE
common_crypt_final(VALUE self, VALUE session, VALUE size, crypt_final_func func)
{
  CK_RV rv;
  CK_ULONG sz = 0;
  VALUE buf;

  if (NIL_P(size)){
    CallFunction(C_EncryptFinal, func, rv, NUM2HANDLE(session), NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(self,rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  CallFunction(C_EncryptFinal, func, rv, NUM2HANDLE(session), (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(self,rv);
  rb_str_set_len(buf, sz);

  return buf;
}

static VALUE
common_sign_update(VALUE self, VALUE session, VALUE data, sign_update_func func)
{
  CK_RV rv;

  StringValue(data);
  CallFunction(C_SignUpdate, func, rv, NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return Qnil;
}

static VALUE
common_verify(VALUE self, VALUE session, VALUE data, VALUE sig, verify_func func)
{
  CK_RV rv;

  StringValue(data);
  StringValue(sig);
  /* Use the function signature of any of the various C_Verify* functions. */
  CallFunction(C_Verify, func, rv, NUM2HANDLE(session),
            (CK_BYTE_PTR)RSTRING_PTR(data), RSTRING_LEN(data),
            (CK_BYTE_PTR)RSTRING_PTR(sig), RSTRING_LEN(sig));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return Qnil;
}

////

static VALUE
pkcs11_C_EncryptInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_EncryptInit func;
  GetFunction(self, C_EncryptInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Encrypt(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Encrypt func;
  GetFunction(self, C_Encrypt, func);
  return common_crypt(self, session, data, size, func);
}

static VALUE
pkcs11_C_EncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_EncryptUpdate func;
  GetFunction(self, C_EncryptUpdate, func);
  return common_crypt_update(self, session, data, size, func);
}

static VALUE
pkcs11_C_EncryptFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_EncryptFinal func;
  GetFunction(self, C_EncryptFinal, func);
  return common_crypt_final(self, session, size, func);
}

static VALUE
pkcs11_C_DecryptInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_DecryptInit func;
  GetFunction(self, C_DecryptInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Decrypt(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Decrypt func;
  GetFunction(self, C_Decrypt, func);
  return common_crypt(self, session, data, size, func);
}

static VALUE
pkcs11_C_DecryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptUpdate func;
  GetFunction(self, C_DecryptUpdate, func);
  return common_crypt_update(self, session, data, size, func);
}

static VALUE
pkcs11_C_DecryptFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_DecryptFinal func;
  GetFunction(self, C_DecryptFinal, func);
  return common_crypt_final(self, session, size, func);
}

#define common_sign(self, s, d, sz, f)            common_crypt(self, s, d, sz, f)
#define common_sign_final(self, s, sz, f)         common_crypt_final(self, s, sz, f)
#define common_verify_update(self, s, d, f)       common_sign_update(self, s, d, f)
#define common_verify_final(self, s, d, f)        common_sign_update(self, s, d, f)
#define common_verify_recover(self, s, d, sz, f)  common_sign(self, s, d, sz, f)

static VALUE
pkcs11_C_SignInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_SignInit func;
  GetFunction(self, C_SignInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Sign(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Sign func;
  GetFunction(self, C_Sign, func);
  return common_sign(self, session, data, size, func);
}

static VALUE
pkcs11_C_SignUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_SignUpdate func;
  GetFunction(self, C_SignUpdate, func);
  common_sign_update(self, session, data, func);
  return self;
}

static VALUE
pkcs11_C_SignFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_SignFinal func;
  GetFunction(self, C_SignFinal, func);
  return common_sign_final(self, session, size, func);
}

static VALUE
pkcs11_C_SignRecoverInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_SignRecoverInit func;
  GetFunction(self, C_SignRecoverInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_SignRecover(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_SignRecover func;
  GetFunction(self, C_SignRecover, func);
  return common_sign(self, session, data, size, func);
}

static VALUE
pkcs11_C_VerifyInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_VerifyInit func;
  GetFunction(self, C_VerifyInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_Verify(VALUE self, VALUE session, VALUE data, VALUE sig)
{
  CK_C_Verify func;
  GetFunction(self, C_Verify, func);
  common_verify(self, session, data, sig, func);
  return Qtrue;
}

static VALUE
pkcs11_C_VerifyUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_VerifyUpdate func;
  GetFunction(self, C_VerifyUpdate, func);
  common_verify_update(self, session, data, func);
  return self;
}

static VALUE
pkcs11_C_VerifyFinal(VALUE self, VALUE session, VALUE sig)
{
  CK_C_VerifyFinal func;
  GetFunction(self, C_VerifyFinal, func);
  common_verify_final(self, session, sig, func);
  return Qtrue;
}

static VALUE
pkcs11_C_VerifyRecoverInit(VALUE self, VALUE session, VALUE mechanism, VALUE key)
{
  CK_C_VerifyRecoverInit func;
  GetFunction(self, C_VerifyRecoverInit, func);
  common_init(self, session, mechanism, key, func);
  return self;
}

static VALUE
pkcs11_C_VerifyRecover(VALUE self, VALUE session, VALUE sig, VALUE size)
{
  CK_C_VerifyRecover func;
  GetFunction(self, C_VerifyRecover, func);
  common_verify_recover(self, session, sig, size, func);
  return Qtrue;
}

#define common_digest(self, s, d, sz, f)      common_crypt(self, s, d, sz, f)
#define common_digest_update(self, s, d, f)   common_sign_update(self, s, d, f)
#define common_digest_final(self, s, sz, f)   common_crypt_final(self, s, sz, f)

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
  CallFunction(C_DigestInit, func, rv, NUM2HANDLE(session), m);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

VALUE
pkcs11_C_Digest(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_Digest func;
  GetFunction(self, C_Digest, func);
  return common_digest(self, session, data, size, func);
}

VALUE
pkcs11_C_DigestUpdate(VALUE self, VALUE session, VALUE data)
{
  CK_C_DigestUpdate func;
  GetFunction(self, C_DigestUpdate, func);
  common_digest_update(self, session, data, func);
  return self;
}

VALUE
pkcs11_C_DigestKey(VALUE self, VALUE session, VALUE handle)
{
  CK_C_DigestKey func;
  CK_RV rv;

  GetFunction(self, C_DigestKey, func);
  CallFunction(C_DigestKey, func, rv, NUM2HANDLE(session), NUM2HANDLE(handle));
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return self;
}

VALUE
pkcs11_C_DigestFinal(VALUE self, VALUE session, VALUE size)
{
  CK_C_DigestFinal func;
  GetFunction(self, C_DigestFinal, func);
  return common_digest_final(self, session, size, func);
}

VALUE
pkcs11_C_DigestEncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DigestEncryptUpdate func;
  GetFunction(self, C_DigestEncryptUpdate, func);
  return common_crypt_update(self, session, data, size, func);
}

VALUE
pkcs11_C_DecryptDigestUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptDigestUpdate func;
  GetFunction(self, C_DecryptDigestUpdate, func);
  return common_crypt_update(self, session, data, size, func);
}

VALUE
pkcs11_C_SignEncryptUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_SignEncryptUpdate func;
  GetFunction(self, C_SignEncryptUpdate, func);
  return common_crypt_update(self, session, data, size, func);
}

VALUE
pkcs11_C_DecryptVerifyUpdate(VALUE self, VALUE session, VALUE data, VALUE size)
{
  CK_C_DecryptVerifyUpdate func;
  GetFunction(self, C_DecryptVerifyUpdate, func);
  return common_crypt_update(self, session, data, size, func);
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
  CallFunction(C_GenerateKey, func, rv, NUM2HANDLE(session), m, tmp, RARRAY_LEN(template), &handle);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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

  CallFunction(C_GenerateKeyPair, func, rv, NUM2HANDLE(session), m,
            pubkey_tmp, RARRAY_LEN(pubkey_template),
            privkey_tmp, RARRAY_LEN(privkey_template),
            &pubkey_handle, &privkey_handle);
  free(pubkey_tmp);
  free(privkey_tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);
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
    CallFunction(C_WrapKey, func, rv, NUM2HANDLE(session), m,
              NUM2HANDLE(wrapping), NUM2HANDLE(wrapped),
              (CK_BYTE_PTR)NULL_PTR, &sz);
    if(rv != CKR_OK) pkcs11_raise(self,rv);
  }else{
    sz = NUM2ULONG(size);
  }
  buf = rb_str_new(0, sz);

  CallFunction(C_WrapKey, func, rv, NUM2HANDLE(session), m,
            NUM2HANDLE(wrapping), NUM2HANDLE(wrapped),
            (CK_BYTE_PTR)RSTRING_PTR(buf), &sz);
  if(rv != CKR_OK) pkcs11_raise(self,rv);
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
  CallFunction(C_UnwrapKey, func, rv, NUM2HANDLE(session), m, NUM2HANDLE(wrapping),
            (CK_BYTE_PTR)RSTRING_PTR(wrapped), RSTRING_LEN(wrapped),
            tmp, RARRAY_LEN(template), &h);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

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
  CallFunction(C_DeriveKey, func, rv, NUM2HANDLE(session), m, NUM2HANDLE(base),
            tmp, RARRAY_LEN(template), &h);
  free(tmp);
  if(rv != CKR_OK) pkcs11_raise(self,rv);

  return HANDLE2NUM(h);
}

/* rb_define_method(cPKCS11, "vendor_raise_on_return_value", pkcs11_vendor_raise_on_return_value, 1); */
/*
 * Raise an exception for the given PKCS#11 return value. This method can be overloaded
 * to raise vendor specific exceptions. It is only called for rv!=0 and it should never
 * return regulary, but always by an exception.
 * @param [Integer] rv return value of the latest operation
 */
static VALUE
pkcs11_vendor_raise_on_return_value(VALUE self, VALUE rv_value)
{
  VALUE class;
  CK_RV rv = NUM2ULONG(rv_value);
  class = pkcs11_return_value_to_class(rv, ePKCS11Error);
  rb_raise(class, "%lu", rv);

  return Qnil;
}


/* rb_define_method(cPKCS11, "vendor_class_CK_ATTRIBUTE", pkcs11_vendor_class_CK_ATTRIBUTE, 0); */
/*
 * Return class CK_ATTRIBUTE. This method can be overloaded
 * to return a derived class that appropriate converts vendor specific attributes.
 * @return [CK_ATTRIBUTE] some kind of CK_ATTRIBUTE
 */
static VALUE
pkcs11_vendor_class_CK_ATTRIBUTE(VALUE self)
{
  return cCK_ATTRIBUTE;
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
  case T_BIGNUM:
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

/* rb_define_method(cCK_ATTRIBUTE, "type", ck_attr_type, 0); */
/*
 * @return [Integer] attribute type PKCS11::CKA_*
 */
static VALUE
ck_attr_type(VALUE self)
{
  CK_ATTRIBUTE *attr;
  Data_Get_Struct(self, CK_ATTRIBUTE, attr);
  return ULONG2NUM(attr->type);
}

/* rb_define_method(cCK_ATTRIBUTE, "value", ck_attr_value, 0); */
/*
 * @return [String, Integer, Boolean] attribute value
 * @see PKCS11::Object#[]
 */
static VALUE
ck_attr_value(VALUE self)
{
  CK_ATTRIBUTE *attr;
  Data_Get_Struct(self, CK_ATTRIBUTE, attr);
  if (attr->ulValueLen == 0) return Qnil;
  switch(attr->type){
  case CKA_ALWAYS_AUTHENTICATE:
  case CKA_ALWAYS_SENSITIVE:
  case CKA_COLOR:
/*  case CKA_COPYABLE: v2.3 */
  case CKA_DECRYPT:
  case CKA_DERIVE:
  case CKA_ENCRYPT:
  case CKA_EXTRACTABLE:
  case CKA_HAS_RESET:
  case CKA_LOCAL:
  case CKA_MODIFIABLE:
  case CKA_NEVER_EXTRACTABLE:
  case CKA_OTP_USER_FRIENDLY_MODE:
  case CKA_PRIVATE:
  case CKA_SENSITIVE:
  case CKA_SIGN:
  case CKA_SIGN_RECOVER:
  case CKA_TOKEN:
  case CKA_TRUSTED:
  case CKA_UNWRAP:
  case CKA_VERIFY:
  case CKA_VERIFY_RECOVER:
  case CKA_WRAP:
  case CKA_WRAP_WITH_TRUSTED:
    if (attr->ulValueLen == sizeof(CK_BBOOL))
      return (*(CK_BBOOL*)(attr->pValue)) == CK_TRUE ? Qtrue : Qfalse;
    break;
  case CKA_BITS_PER_PIXEL:
  case CKA_CERTIFICATE_CATEGORY:
  case CKA_CERTIFICATE_TYPE:
  case CKA_CHAR_COLUMNS:
  case CKA_CHAR_ROWS:
  case CKA_CLASS:
  case CKA_HW_FEATURE_TYPE:
  case CKA_JAVA_MIDP_SECURITY_DOMAIN:
  case CKA_KEY_TYPE:
  case CKA_MECHANISM_TYPE:
  case CKA_MODULUS_BITS:
  case CKA_OTP_CHALLENGE_REQUIREMENT:
  case CKA_OTP_COUNTER_REQUIREMENT:
  case CKA_OTP_FORMAT:
  case CKA_OTP_LENGTH:
  case CKA_OTP_PIN_REQUIREMENT:
  case CKA_OTP_TIME_INTERVAL:
  case CKA_OTP_TIME_REQUIREMENT:
  case CKA_OTP_SERVICE_LOGO_TYPE:
  case CKA_PIXEL_X:
  case CKA_PIXEL_Y:
  case CKA_PRIME_BITS:
  case CKA_RESOLUTION:
  case CKA_SUBPRIME_BITS:
  case CKA_VALUE_BITS:
  case CKA_VALUE_LEN:
  if (attr->ulValueLen == sizeof(CK_ULONG))
      return ULONG2NUM(*(CK_ULONG_PTR)(attr->pValue));
    break;
  case CKA_LABEL:
  case CKA_APPLICATION:
  case CKA_URL:
  case CKA_CHAR_SETS:
  case CKA_ENCODING_METHODS:
  case CKA_MIME_TYPES:
    return rb_enc_str_new(attr->pValue, attr->ulValueLen, rb_utf8_encoding());
  }
  return rb_str_new(attr->pValue, attr->ulValueLen);
}

///////////////////////////////////////

#include "pk11_struct_impl.inc"

///////////////////////////////////////

PKCS11_IMPLEMENT_ALLOCATOR(CK_MECHANISM)

/*
 * Spezifies a particularly crypto mechanism.
 * @param [Integer, nil] mechanism The mechanism to use (PKCS11::CKM_*)
 * @param [String, Integer, PKCS11::CStruct, nil] pParameter optional parameter to the mechanism
 */
static VALUE
cCK_MECHANISM_initialize(int argc, VALUE *argv, VALUE self)
{
  VALUE type, param;

  rb_scan_args(argc, argv, "02", &type, &param);
  rb_funcall(self, rb_intern("mechanism="), 1, type);
  rb_funcall(self, rb_intern("pParameter="), 1, param);

  return self;
}

/* rb_define_method(cCK_MECHANISM, "mechanism", cCK_MECHANISM_get_mechanism, 0); */
/* rb_define_method(cCK_MECHANISM, "mechanism=", cCK_MECHANISM_set_mechanism, 1); */
PKCS11_IMPLEMENT_ULONG_ACCESSOR(CK_MECHANISM, mechanism);

/* rb_define_method(cCK_MECHANISM, "pParameter", cCK_MECHANISM_get_pParameter, 0); */
/* rb_define_method(cCK_MECHANISM, "pParameter=", cCK_MECHANISM_set_pParameter, 1); */
/* @see PKCS11::CK_MECHANISM#initialize */
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
  CK_ULONG ulong_val;

  switch(TYPE(value)){
  case T_NIL:
    m->pParameter = NULL_PTR;
    m->ulParameterLen = 0;
    break;
  case T_STRING:
    value = rb_obj_freeze(rb_str_dup(value));
    m->pParameter = RSTRING_PTR(value);
    m->ulParameterLen = RSTRING_LEN(value);
    break;
  case T_FIXNUM:
  case T_BIGNUM:
    ulong_val = NUM2ULONG(value);
    value = rb_obj_freeze(rb_str_new((char*)&ulong_val, sizeof(ulong_val)));
    m->pParameter = RSTRING_PTR(value);
    m->ulParameterLen = RSTRING_LEN(value);
    break;
  case T_DATA:
    m->ulParameterLen = NUM2LONG(rb_const_get(rb_funcall(value, rb_intern("class"), 0), rb_intern("SIZEOF_STRUCT")));
    m->pParameter = DATA_PTR(value);
    break;
  default:
    rb_raise(rb_eArgError, "invalid argument");
  }
  /* don't GC the value as long as this object is active */
  rb_iv_set(self, "pParameter", value);

  return value;
}


void
Init_pkcs11_ext(void)
{
  mPKCS11 = rb_define_module("PKCS11");
  sNEW = rb_intern("new");
  cPKCS11 = rb_define_class_under(mPKCS11, "Library", rb_cObject);

/* Document-method: PKCS11.open
 *
 * Alias function for {PKCS11::Library#initialize}
 */
  rb_define_module_function(mPKCS11, "open", pkcs11_library_new, -1);

  /* Library version */
  rb_define_const( mPKCS11, "VERSION", rb_str_new2(VERSION) );

  /* Document-class: PKCS11::Error
   *
   * Base class for all Cryptoki exceptions (CKR_*)  */
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
  PKCS11_DEFINE_METHOD(C_CopyObject, 3);
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
  PKCS11_DEFINE_METHOD(vendor_raise_on_return_value, 1);
  PKCS11_DEFINE_METHOD(vendor_class_CK_ATTRIBUTE, 0);

  ///////////////////////////////////////

  cCStruct = rb_define_class_under(mPKCS11, "CStruct", rb_cObject);

  cCK_ATTRIBUTE = rb_define_class_under(mPKCS11, "CK_ATTRIBUTE", rb_cObject);
  rb_define_alloc_func(cCK_ATTRIBUTE, ck_attr_s_alloc);
  rb_define_method(cCK_ATTRIBUTE, "initialize", ck_attr_initialize, -1);
  rb_define_method(cCK_ATTRIBUTE, "type", ck_attr_type, 0);
  rb_define_method(cCK_ATTRIBUTE, "value", ck_attr_value, 0);

  /* Document-class: PKCS11::CK_MECHANISM
   *
   * Describes a crypto mechanism CKM_* with optional parameters. */
  /* cCK_MECHANISM = rb_define_class_under(mPKCS11, "CK_MECHANISM", rb_cObject); */
  PKCS11_DEFINE_STRUCT(CK_MECHANISM);
  rb_define_method(cCK_MECHANISM, "initialize", cCK_MECHANISM_initialize, -1);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM, mechanism);
  PKCS11_DEFINE_MEMBER(CK_MECHANISM, pParameter);

  #include "pk11_struct_def.inc"

  Init_pkcs11_const(mPKCS11, ePKCS11Error);
}
