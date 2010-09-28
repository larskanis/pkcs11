#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 structs and
# generator for Ruby wrapper classes.

require 'optparse'

options = Struct.new(:verbose, :def, :impl, :const).new
OptionParser.new do |opts|
	opts.banner = "Usage: #{$0} [options] <header-file.h>*"

	opts.on("-v", "--[no-]verbose", "Run verbosely", &options.method(:verbose=))
	opts.on("--def FILE", "Write struct definitions to this file", &options.method(:def=))
  opts.on("--impl FILE", "Write struct implementations to this file", &options.method(:impl=))
  opts.on("--const FILE", "Write const implementations to this file", &options.method(:const=))
	opts.on_tail("-h", "--help", "Show this message") do
		puts opts
		exit
	end
end.parse!

Attribute = Struct.new(:type, :name, :qual)
IgnoreStructs = %w[CK_MECHANISM_INFO CK_VERSION CK_C_INITIALIZE_ARGS CK_MECHANISM CK_ATTRIBUTE CK_INFO CK_SLOT_INFO CK_TOKEN_INFO CK_MECHANISM_INFO CK_SESSION_INFO]

structs = {}
File.open(options.def, "w") do |fd_def|
File.open(options.impl, "w") do |fd_impl|
ARGV.each do |file_h|
	c_src = IO.read(file_h)
	c_src.scan(/struct\s+([A-Z_0-9]+)\s*\{(.*?)\}/m) do |struct|
		struct_name, struct_text = $1, $2
		next if IgnoreStructs.include?(struct_name)
		
		fd_impl.puts "PKCS11_IMPLEMENT_STRUCT_WITH_ALLOCATOR(#{struct_name});"
		fd_def.puts "PKCS11_DEFINE_STRUCT(#{struct_name});"
	
		attrs = {}
		struct_text.scan(/^\s+([A-Z_0-9]+)\s+([\w_]+)\s*(\[\s*(\d+)\s*\])?/) do |elem|
			attr = Attribute.new($1, $2, $4)
			attrs[$1+" "+$2] = attr
# 			puts attr.inspect
		end

    structs[struct_name] = attrs
		
		# try to find attributes belonging together
		attrs.select{|key, attr| ['CK_BYTE_PTR', 'CK_VOID_PTR', 'CK_UTF8CHAR_PTR'].include?(attr.type) }.each do |key, attr|
			if len_attr=attrs["CK_ULONG #{attr.name.gsub(/^p/, "ul")}Len"]
				fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_LEN_ACCESSOR(#{struct_name}, #{attr.name}, #{len_attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
				attrs.delete_if{|k,v| v==len_attr}
			elsif attr.name=='pData' && (len_attr = attrs["CK_ULONG length"] || attrs["CK_ULONG ulLen"])
				fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_LEN_ACCESSOR(#{struct_name}, #{attr.name}, #{len_attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
				attrs.delete_if{|k,v| v==len_attr}
			else
				fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			end
			attrs.delete_if{|k,v| v==attr}
		end
		
		# standalone attributes
		attrs.each do |key, attr|
			case attr.type
			when 'CK_BYTE', 'CK_UTF8CHAR', 'CK_CHAR'
				fd_impl.puts "PKCS11_IMPLEMENT_STRING_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			when 'CK_ULONG', 'CK_FLAGS', 'CK_SLOT_ID', 'CK_STATE', /CK_[A-Z_0-9]+_TYPE/
				fd_impl.puts "PKCS11_IMPLEMENT_ULONG_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			when 'CK_OBJECT_HANDLE'
				fd_impl.puts "PKCS11_IMPLEMENT_HANDLE_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			when 'CK_BBOOL'
				fd_impl.puts "PKCS11_IMPLEMENT_BOOL_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			when 'CK_VERSION'
				fd_impl.puts "PKCS11_IMPLEMENT_VERSION_ACCESSOR(#{struct_name}, #{attr.name});"
				fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
			else
        if structs[attr.type]
          fd_impl.puts "PKCS11_IMPLEMENT_STRUCT_ACCESSOR(#{struct_name}, #{attr.type}, #{attr.name});"
          fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct_name}, #{attr.name});"
        else
          fd_impl.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
          fd_def.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
        end
			end
		end
	
		fd_impl.puts
		fd_def.puts
	end
end
end
end

ConstTemplate = Struct.new :regexp, :def
ConstGroups = [
  ConstTemplate.new(/#define\s+(CKM_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_MECHANISM'),
  ConstTemplate.new(/#define\s+(CKA_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_ATTRIBUTE'),
  ConstTemplate.new(/#define\s+(CKO_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_OBJECT_CLASS'),
  ConstTemplate.new(/#define\s+(CKR_[A-Z_0-9]+)\s+(\w+)/, 'PKCS11_DEFINE_RETURN_VALUE'),
]

File.open(options.const, "w") do |fd_const|
ARGV.each do |file_h|
  c_src = IO.read(file_h)
  ConstGroups.each do |const_group|
    c_src.scan(const_group.regexp) do
      const_name, const_value = $1, $2
      
      fd_const.puts "#{const_group.def}(#{const_name}); /* #{const_value} */"
    end
  end
end
end
