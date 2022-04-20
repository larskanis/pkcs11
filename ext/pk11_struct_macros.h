#ifndef PK11_STRUCT_MACROS_INCLUDED
#define PK11_STRUCT_MACROS_INCLUDED

/**************************************************/
/* struct/attribute implementation                */
/**************************************************/

#define HANDLE2NUM(n) ULONG2NUM(n)
#define NUM2HANDLE(n) PKNUM2ULONG(n)
#define PKNUM2ULONG(n) pkcs11_num2ulong(n)

static VALUE
pkcs11_num2ulong(VALUE val)
{
  if (TYPE(val) == T_BIGNUM || TYPE(val) == T_FIXNUM) {
    return NUM2ULONG(val);
  }
  return NUM2ULONG(rb_to_int(val));
}

static VALUE
get_string(VALUE obj, off_t offset, size_t size, rb_encoding *enc)
{
  char *ptr = (char*)DATA_PTR(obj);
  return rb_enc_str_new(ptr+offset, size, enc);
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
get_byte(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  return ULONG2NUM(*(CK_BYTE_PTR)(ptr+offset));
}

static VALUE
set_byte(VALUE obj, VALUE value, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  *(CK_BYTE_PTR)(ptr+offset) = NUM2ULONG(value);
  return value;
}

static VALUE
get_ulong_ptr(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  CK_ULONG_PTR p = *(CK_ULONG_PTR *)(ptr+offset);
  if (!p) return Qnil;
  return ULONG2NUM(*p);
}

static VALUE
set_ulong_ptr(VALUE obj, VALUE value, const char *name, off_t offset)
{
  VALUE new_obj;
  CK_ULONG_PTR *ptr = (CK_ULONG_PTR *)((char*)DATA_PTR(obj) + offset);
  if (NIL_P(value)){
    rb_iv_set(obj, name, value);
    *ptr = NULL_PTR;
    return value;
  }
  new_obj = Data_Make_Struct(rb_cObject, CK_ULONG, 0, -1, *ptr);
  rb_iv_set(obj, name, new_obj);
  **ptr = NUM2ULONG(value);
  return value;
}

static VALUE
get_handle(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  return HANDLE2NUM(*(CK_OBJECT_HANDLE_PTR)(ptr+offset));
}

static VALUE
set_handle(VALUE obj, VALUE value, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  *(CK_OBJECT_HANDLE_PTR)(ptr+offset) = NUM2HANDLE(value);
  return value;
}

static VALUE
get_bool(VALUE obj, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  if(*(CK_BBOOL*)(ptr+offset)) return Qtrue;
  else return Qfalse;
}

static VALUE
set_bool(VALUE obj, VALUE value, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  if(value == Qfalse) *(CK_BBOOL*)(ptr+offset) = 0;
  else if(value == Qtrue) *(CK_BBOOL*)(ptr+offset) = 1;
  else rb_raise(rb_eArgError, "arg must be true or false");
  return value;
}

static VALUE
get_string_ptr(VALUE obj, const char *name, off_t offset, rb_encoding *enc)
{
  char *ptr = (char*)DATA_PTR(obj);
  char *p = *(char**)(ptr+offset);
  if (!p) return Qnil;
  return rb_enc_str_new_cstr(p, enc);
}

static VALUE
set_string_ptr(VALUE obj, VALUE value, const char *name, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj);
  if (NIL_P(value)){
    rb_iv_set(obj, name, value);
    *(CK_VOID_PTR*)(ptr+offset) = NULL_PTR;
    return value;
  }
  StringValue(value);
  value = rb_obj_freeze(rb_str_dup(value));
  rb_iv_set(obj, name, value);
  *(CK_VOID_PTR*)(ptr+offset) = RSTRING_PTR(value);
  return value;
}

static VALUE
get_string_ptr_len(VALUE obj, const char *name, off_t offset, off_t offset_len, rb_encoding *enc)
{
  unsigned long l;
  char *ptr = (char*)DATA_PTR(obj);
  char *p = *(char**)(ptr+offset);
  if (!p) return Qnil;
  l = *(unsigned long*)(ptr+offset_len);
  return rb_enc_str_new(p, l, enc);
}

static VALUE
set_string_ptr_len(VALUE obj, VALUE value, const char *name, off_t offset, off_t offset_len)
{
  char *ptr = (char*)DATA_PTR(obj);
  if (NIL_P(value)){
    rb_iv_set(obj, name, value);
    *(CK_VOID_PTR*)(ptr+offset) = NULL_PTR;
    *(unsigned long*)(ptr+offset_len) = 0;
    return value;
  }
  StringValue(value);
  value = rb_obj_freeze(rb_str_dup(value));
  rb_iv_set(obj, name, value);
  *(CK_VOID_PTR*)(ptr+offset) = RSTRING_PTR(value);
  *(unsigned long*)(ptr+offset_len) = RSTRING_LEN(value);
  return value;
}

static VALUE
get_struct_inline(VALUE obj, VALUE klass, const char *name, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj) + offset;
  VALUE inline_obj = Data_Wrap_Struct(klass, 0, 0, ptr);
  rb_iv_set(inline_obj, name, obj);
  return inline_obj;
}

static VALUE
set_struct_inline(VALUE obj, VALUE klass, const char *struct_name, VALUE value, const char *name, off_t offset, int sizeofstruct)
{
  char *ptr = (char*)DATA_PTR(obj) + offset;
  if (!rb_obj_is_kind_of(value, klass))
    rb_raise(rb_eArgError, "arg must be a PKCS11::%s", struct_name);
  memcpy(ptr, DATA_PTR(value), sizeofstruct);
  return value;
}

static VALUE
get_struct_ptr(VALUE obj, VALUE klass, const char *name, off_t offset, int sizeofstruct)
{
  char *ptr = (char*)DATA_PTR(obj);
  char *p = *(char**)(ptr+offset);
  void *mem;
  VALUE new_obj;
  if (!p) return Qnil;
  mem = xmalloc(sizeofstruct);
  memcpy(mem, p, sizeofstruct);
  new_obj = Data_Wrap_Struct(klass, 0, -1, mem);
  return new_obj;
}

static VALUE
set_struct_ptr(VALUE obj, VALUE klass, const char *struct_name, VALUE value, const char *name, off_t offset)
{
  char *ptr = (char*)DATA_PTR(obj) + offset;
  if (NIL_P(value)){
    rb_iv_set(obj, name, value);
    *(CK_VOID_PTR*)ptr = NULL_PTR;
    return value;
  }
  if (!rb_obj_is_kind_of(value, klass))
    rb_raise(rb_eArgError, "arg must be a PKCS11::%s", struct_name);
  *(CK_VOID_PTR*)ptr = DATA_PTR(value);
  rb_iv_set(obj, name, value);
  return value;
}

static VALUE
get_struct_ptr_array(VALUE obj, VALUE klass, off_t offset, off_t offset_len, int sizeofstruct)
{
  unsigned long i;
  char *ptr = DATA_PTR(obj);
  char *p = *(char **)(ptr+offset);
  unsigned long l = *(unsigned long*)(ptr+offset_len);
  VALUE ary = rb_ary_new();
  for (i = 0; i < l; i++){
    VALUE new_obj;
    void *mem = xmalloc(sizeofstruct);
    memcpy(mem, p + sizeofstruct * i, sizeofstruct);
    new_obj = Data_Wrap_Struct(klass, 0, -1, mem);
    rb_ary_push(ary, new_obj);
  }
  return ary;
}

static VALUE
set_struct_ptr_array(VALUE obj, VALUE klass, const char *struct_name, VALUE value, const char *name, off_t offset, off_t offset_len, int sizeofstruct)
{
  int i;
  VALUE str_buf;
  char *ptr = DATA_PTR(obj);
  Check_Type(value, T_ARRAY);

  str_buf = rb_str_buf_new(sizeofstruct * RARRAY_LEN(value));

  for (i = 0; i < RARRAY_LEN(value); i++){
    VALUE entry = rb_ary_entry(value, i);
    if (!rb_obj_is_kind_of(entry, klass))
      rb_raise(rb_eArgError, "arg must be array of PKCS11::%s", struct_name);
    memcpy(RSTRING_PTR(str_buf) + sizeofstruct * i, DATA_PTR(entry), sizeofstruct);
  }
  *(CK_VOID_PTR*)(ptr+offset) = RSTRING_PTR(str_buf);
  *(unsigned long*)(ptr+offset_len) = RARRAY_LEN(value);
  rb_iv_set(obj, name, str_buf);
  return value;
}


#define OFFSET_OF(s, f) ((off_t)((char*)&(((s*)0)->f) - (char*)0))
#define SIZE_OF(s, f) (sizeof(((s*)0)->f))

#define PKCS11_IMPLEMENT_ALLOCATOR(s) \
static VALUE s##_s_alloc(VALUE self){ \
  s *info; \
  VALUE obj = Data_Make_Struct(self, s, 0, -1, info); \
  return obj; \
} \
static VALUE c##s##_to_s(VALUE self){ \
  return rb_str_new(DATA_PTR(self), sizeof(s)); \
} \
static VALUE c##s##_members(VALUE self){ \
  return a##s##_members; \
}

#define PKCS11_IMPLEMENT_STRUCT_WITH_ALLOCATOR(s) \
static VALUE c##s;\
static VALUE a##s##_members;\
PKCS11_IMPLEMENT_ALLOCATOR(s);

#define PKCS11_IMPLEMENT_STRING_ACCESSOR(s, f, enco) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_string(o, OFFSET_OF(s, f), SIZE_OF(s, f), rb_##enco##_encoding()); \
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

#define PKCS11_IMPLEMENT_BYTE_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_byte(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_byte(o, v, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_ULONG_PTR_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_ulong_ptr(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_ulong_ptr(o, v, #f, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_HANDLE_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_handle(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_handle(o, v, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_BOOL_ACCESSOR(s, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_bool(o, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_bool(o, v, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_STRING_PTR_ACCESSOR(s, f, enco) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_string_ptr(o, #f, OFFSET_OF(s, f), rb_##enco##_encoding()); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_string_ptr(o, v, #f, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_STRING_PTR_LEN_ACCESSOR(s, f, l, enco) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_string_ptr_len(o, #f, OFFSET_OF(s, f), OFFSET_OF(s, l), rb_##enco##_encoding()); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_string_ptr_len(o, v, #f, OFFSET_OF(s, f), OFFSET_OF(s, l)); \
}

#define PKCS11_IMPLEMENT_STRUCT_ACCESSOR(s, k, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_struct_inline(o, c##k, #f, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_struct_inline(o, c##k, #k, v, #f, OFFSET_OF(s, f), sizeof(k)); \
}

#define PKCS11_IMPLEMENT_PKCS11_STRUCT_ACCESSOR(s, k, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return get_struct_inline(o, klass, #f, OFFSET_OF(s, f)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return set_struct_inline(o, klass, #k, v, #f, OFFSET_OF(s, f), sizeof(k)); \
}

#define PKCS11_IMPLEMENT_STRUCT_PTR_ACCESSOR(s, k, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_struct_ptr(o, c##k, #f, OFFSET_OF(s, f), sizeof(k)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_struct_ptr(o, c##k, #k, v, #f, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_PKCS11_STRUCT_PTR_ACCESSOR(s, k, f) \
static VALUE c##s##_get_##f(VALUE o){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return get_struct_ptr(o, klass, #f, OFFSET_OF(s, f), sizeof(k)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return set_struct_ptr(o, klass, #k, v, #f, OFFSET_OF(s, f)); \
}

#define PKCS11_IMPLEMENT_STRUCT_PTR_ARRAY_ACCESSOR(s, k, f, l) \
static VALUE c##s##_get_##f(VALUE o){ \
  return get_struct_ptr_array(o, c##k, OFFSET_OF(s, f), OFFSET_OF(s, l), sizeof(k)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  return set_struct_ptr_array(o, c##k, #k, v, #f, OFFSET_OF(s, f), OFFSET_OF(s, l), sizeof(k)); \
}

#define PKCS11_IMPLEMENT_PKCS11_STRUCT_PTR_ARRAY_ACCESSOR(s, k, f, l) \
static VALUE c##s##_get_##f(VALUE o){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return get_struct_ptr_array(o, klass, OFFSET_OF(s, f), OFFSET_OF(s, l), sizeof(k)); \
} \
static VALUE c##s##_set_##f(VALUE o, VALUE v){ \
  VALUE klass = rb_const_get(rb_const_get(rb_cObject, rb_intern("PKCS11")), rb_intern(#k)); \
  return set_struct_ptr_array(o, klass, #k, v, #f, OFFSET_OF(s, f), OFFSET_OF(s, l), sizeof(k)); \
}


/**************************************************/
/* struct/attribute definition                    */
/**************************************************/

#define PKCS11_DEFINE_STRUCT(s) \
  do { \
    c##s = rb_define_class_under(MODULE_FOR_STRUCTS, #s, BASECLASS_FOR_STRUCTS); \
    rb_global_variable(&a##s##_members); \
    a##s##_members = rb_ary_new(); \
    rb_define_alloc_func(c##s, s##_s_alloc); \
    rb_define_const(c##s, "SIZEOF_STRUCT", ULONG2NUM(sizeof(s))); \
    rb_define_method(c##s, "to_s", c##s##_to_s, 0); \
    rb_define_method(c##s, "members", c##s##_members, 0); \
    rb_iv_set(c##s, "members", a##s##_members); \
  } while(0)

#define PKCS11_DEFINE_MEMBER(s, f) \
  do { \
    rb_define_method(c##s, #f, c##s##_get_##f, 0); \
    rb_define_method(c##s, #f "=", c##s##_set_##f, 1); \
    rb_ary_push(a##s##_members, rb_str_new2(#f)); \
  } while(0)


#endif
