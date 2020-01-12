#!/usr/bin/env ruby
# Quick and dirty parser for PKCS#11 structs and
# generator for Ruby wrapper classes.

require 'optparse'

module PKCS11
class StructParser

  attr_accessor :options
  attr_accessor :structs
  attr_accessor :structs_by_name
  attr_accessor :std_structs_by_name

  def self.run(argv)
    s = self.new
    options = Struct.new(:verbose, :def, :impl, :doc, :files).new
    OptionParser.new do |opts|
      opts.banner = "Usage: #{$0} [options] <header-file.h>*"

      opts.on("-v", "--[no-]verbose", "Run verbosely", &options.method(:verbose=))
      opts.on("--def FILE", "Write struct definitions to this file", &options.method(:def=))
      opts.on("--impl FILE", "Write struct implementations to this file", &options.method(:impl=))
      opts.on("--doc FILE", "Write documentation to this file", &options.method(:doc=))
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
    end.parse!(argv)
    options.files = argv
    s.options = options
    s.start!
  end

  CStruct = Struct.new(:name, :attrs)
  Attribute = Struct.new(:type, :name, :qual, :mark)
  IgnoreStructs = %w[CK_ATTRIBUTE CK_MECHANISM]
  OnlyAllocatorStructs = %w[CK_MECHANISM_INFO CK_C_INITIALIZE_ARGS CK_INFO CK_SLOT_INFO CK_TOKEN_INFO CK_SESSION_INFO]

  def struct_module
    'PKCS11'
  end

  class CStruct
    def attr_by_sign(key)
      attrs.find{|a| a.type+" "+a.name==key }
    end
  end

  class Attribute
    def type_noptr
      type.gsub(/_PTR$/,'')
    end
  end

  def parse_files(files)
    structs = []
    files.each do |file_h|
      c_src = IO.read(file_h)
      c_src.scan(/struct\s+([A-Z_0-9]+)\s*\{(.*?)\}/m) do |struct|
        struct_text = $2
        struct = CStruct.new( $1, [] )

        struct_text.scan(/^\s+([A-Z_0-9]+)\s+([\w_]+)\s*(\[\s*(\d+)\s*\])?/) do |elem|
          struct.attrs << Attribute.new($1, $2, $4)
        end
        structs << struct
      end
    end
    return structs
  end

  def start!
    @structs = parse_files(options.files)
    @structs_by_name = @structs.inject({}){|sum, v| sum[v.name]=v; sum }
    @std_structs_by_name = @structs_by_name.dup

    write_files
  end

  def array_attribute_names; ['pParams']; end

  def write_files
    File.open(options.def, "w") do |fd_def|
    File.open(options.impl, "w") do |fd_impl|
    File.open(options.doc, "w") do |fd_doc|
    structs.each do |struct|
      next if IgnoreStructs.include?(struct.name)

      if OnlyAllocatorStructs.include?(struct.name)
        fd_impl.puts "PKCS11_IMPLEMENT_ALLOCATOR(#{struct.name});"
      else
        fd_impl.puts "PKCS11_IMPLEMENT_STRUCT_WITH_ALLOCATOR(#{struct.name});"
      end
      fd_def.puts "PKCS11_DEFINE_STRUCT(#{struct.name});"
      fd_doc.puts"class #{struct_module}::#{struct.name} < #{struct_module}::CStruct"
      fd_doc.puts"# Size of corresponding C struct in bytes\nSIZEOF_STRUCT=Integer"
      fd_doc.puts"# @return [String] Binary copy of the C struct\ndef to_s; end"
      fd_doc.puts"# @return [Array<String>] Attributes of this struct\ndef members; end"

      # find attributes belonging together for array of struct
      struct.attrs.select{|attr| structs_by_name[attr.type_noptr] || std_structs_by_name[attr.type_noptr] }.each do |attr|
        if array_attribute_names.include?(attr.name) && (len_attr = struct.attr_by_sign("CK_ULONG ulCount") || struct.attr_by_sign("CK_ULONG count") || struct.attr_by_sign("CK_ULONG #{attr.name}Count"))
          std_struct = "PKCS11_" if std_structs_by_name[attr.type_noptr]
          fd_impl.puts "PKCS11_IMPLEMENT_#{std_struct}STRUCT_PTR_ARRAY_ACCESSOR(#{struct.name}, #{attr.type_noptr}, #{attr.name}, #{len_attr.name});"
          fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
          fd_doc.puts"# @return [Array<PKCS11::#{attr.type_noptr}>] accessor for #{attr.name} and #{len_attr.name}\nattr_accessor :#{attr.name}"
          len_attr.mark = true
          attr.mark = true
        end
      end
      # find string attributes belonging together
      struct.attrs.select{|attr| ['CK_BYTE_PTR', 'CK_VOID_PTR', 'CK_UTF8CHAR_PTR', 'CK_CHAR_PTR'].include?(attr.type) }.each do |attr|
        enco = case attr.type
          when 'CK_UTF8CHAR_PTR' then 'utf8'
          when 'CK_CHAR_PTR' then 'usascii'
          when 'CK_BYTE_PTR', 'CK_VOID_PTR' then 'ascii8bit'
          else raise "unexpected type #{attr.type.inspect}"
        end
        if len_attr=struct.attr_by_sign("CK_ULONG #{attr.name.gsub(/^p([A-Z])/){ "ul"+$1 }}Len")
          fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_LEN_ACCESSOR(#{struct.name}, #{attr.name}, #{len_attr.name}, #{enco});"
          fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
          fd_doc.puts"# @return [#{enco.upcase}-String, nil] accessor for #{attr.name} and #{len_attr.name}\nattr_accessor :#{attr.name}"
          len_attr.mark = true
        elsif attr.name=='pData' && (len_attr = struct.attr_by_sign("CK_ULONG length") || struct.attr_by_sign("CK_ULONG ulLen"))
          fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_LEN_ACCESSOR(#{struct.name}, #{attr.name}, #{len_attr.name}, #{enco});"
          fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
          fd_doc.puts"# @return [#{enco.upcase}-String, nil] accessor for #{attr.name} and #{len_attr.name}\nattr_accessor :#{attr.name}"
          len_attr.mark = true
        else
          fd_impl.puts "PKCS11_IMPLEMENT_STRING_PTR_ACCESSOR(#{struct.name}, #{attr.name}, #{enco});"
          fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
          fd_doc.puts"# @return [#{enco.upcase}-String, nil] accessor for #{attr.name}\nattr_accessor :#{attr.name}"
        end
        attr.mark = true
      end

      # standalone attributes
      struct.attrs.reject{|a| a.mark }.each do |attr|
        if attr.qual
          # Attributes with qualifier
          enco = case attr.type
            when 'CK_BYTE' then 'ascii8bit'
            when 'CK_UTF8CHAR' then 'utf8'
            when 'CK_CHAR' then 'usascii'
          end
          case attr.type
          when 'CK_BYTE', 'CK_UTF8CHAR', 'CK_CHAR'
            fd_impl.puts "PKCS11_IMPLEMENT_STRING_ACCESSOR(#{struct.name}, #{attr.name}, #{enco});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [#{enco.upcase}-String] accessor for #{attr.name} (max #{attr.qual} bytes)\nattr_accessor :#{attr.name}"
          else
            fd_impl.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
            fd_def.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
          end
        else
          case attr.type
          when 'CK_BYTE'
            fd_impl.puts "PKCS11_IMPLEMENT_BYTE_ACCESSOR(#{struct.name}, #{attr.name});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [Integer] accessor for #{attr.name} (CK_BYTE)\nattr_accessor :#{attr.name}"
          when 'CK_ULONG', 'CK_FLAGS', 'CK_SLOT_ID', 'CK_STATE', /CK_[A-Z_0-9]+_TYPE/
            fd_impl.puts "PKCS11_IMPLEMENT_ULONG_ACCESSOR(#{struct.name}, #{attr.name});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [Integer] accessor for #{attr.name} (CK_ULONG)\nattr_accessor :#{attr.name}"
          when 'CK_OBJECT_HANDLE'
            fd_impl.puts "PKCS11_IMPLEMENT_HANDLE_ACCESSOR(#{struct.name}, #{attr.name});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [Integer, PKCS11::Object] Object handle (CK_ULONG)\nattr_accessor :#{attr.name}"
          when 'CK_BBOOL'
            fd_impl.puts "PKCS11_IMPLEMENT_BOOL_ACCESSOR(#{struct.name}, #{attr.name});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [Boolean]  Bool value\nattr_accessor :#{attr.name}"
          when 'CK_ULONG_PTR'
            fd_impl.puts "PKCS11_IMPLEMENT_ULONG_PTR_ACCESSOR(#{struct.name}, #{attr.name});"
            fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
            fd_doc.puts"# @return [Integer, nil] accessor for #{attr.name} (CK_ULONG_PTR)\nattr_accessor :#{attr.name}"
          else
            # Struct attributes
            if structs_by_name[attr.type]
              fd_impl.puts "PKCS11_IMPLEMENT_STRUCT_ACCESSOR(#{struct.name}, #{attr.type}, #{attr.name});"
              fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
              fd_doc.puts"# @return [#{struct_module}::#{attr.type}] inline struct\nattr_accessor :#{attr.name}"
            elsif structs_by_name[attr.type_noptr]
              fd_impl.puts "PKCS11_IMPLEMENT_STRUCT_PTR_ACCESSOR(#{struct.name}, #{attr.type_noptr}, #{attr.name});"
              fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
              fd_doc.puts"# @return [#{struct_module}::#{attr.type_noptr}, nil] pointer to struct\nattr_accessor :#{attr.name}"
            elsif std_structs_by_name[attr.type]
              fd_impl.puts "PKCS11_IMPLEMENT_PKCS11_STRUCT_ACCESSOR(#{struct.name}, #{attr.type}, #{attr.name});"
              fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
              fd_doc.puts"# @return [PKCS11::#{attr.type}] inline struct (see pkcs11.gem)\nattr_accessor :#{attr.name}"
            elsif std_structs_by_name[attr.type_noptr]
              fd_impl.puts "PKCS11_IMPLEMENT_PKCS11_STRUCT_PTR_ACCESSOR(#{struct.name}, #{attr.type_noptr}, #{attr.name});"
              fd_def.puts "PKCS11_DEFINE_MEMBER(#{struct.name}, #{attr.name});"
              fd_doc.puts"# @return [PKCS11::#{attr.type_noptr}, nil] pointer to struct (see pkcs11.gem)\nattr_accessor :#{attr.name}"
            else
              fd_impl.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
              fd_def.puts "/* unimplemented attr #{attr.type} #{attr.name} #{attr.qual} */"
            end
          end
        end
      end

      fd_impl.puts
      fd_def.puts
      fd_doc.puts "end"
    end
    end
    end
    end
  end
end
end

if $0==__FILE__
  PKCS11::StructParser.run(ARGV)
end
