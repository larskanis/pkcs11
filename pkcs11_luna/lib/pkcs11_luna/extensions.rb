#!/usr/bin/env ruby

module PKCS11
module Luna
  # Derive CK_ATTRIBUTE to get converted attributes.
  class CK_ATTRIBUTE < PKCS11::CK_ATTRIBUTE
    
    ATTRIBUTES = {
      CKA_CCM_PRIVATE => :bool,
      CKA_X9_31_GENERATED => :bool,
      CKA_USAGE_COUNT => :ulong,
      CKA_USAGE_LIMIT => :ulong
    }

    def value
      case ATTRIBUTES[type]
        when :bool
          super != "\0"
        when :ulong
          super.unpack("L!")[0]
        else
          super
      end
    end
  end

  # A Luna::Library instance holds a handle to the opened +cryptoki.dll+ or +cryptoki.so+ file.
  #
  # This class is derived from
  # PKCS11::Library[http://pkcs11.rubyforge.org/pkcs11/PKCS11/Library.html] of pkcs11.gem.
  class Library < PKCS11::Library
    MechanismParameters = {
      CKM_AES_GCM => CK_AES_GCM_PARAMS,
      CKM_ECIES => CK_ECIES_PARAMS,
      CKM_XOR_BASE_AND_DATA_W_KDF => CK_XOR_BASE_DATA_KDF_PARAMS,
      CKM_PRF_KDF => CK_PRF_KDF_PARAMS,
      CKM_NIST_PRF_KDF => CK_PRF_KDF_PARAMS,
      CKM_SEED_CTR => CK_AES_CTR_PARAMS,
      CKM_AES_CTR => CK_AES_CTR_PARAMS,
      CKM_DES3_CTR => CK_DES_CTR_PARAMS,
      CKM_AES_GMAC => CK_AES_GCM_PARAMS,
      CKM_AES_CBC_PAD_EXTRACT => CK_AES_CBC_PAD_EXTRACT_PARAMS,
      CKM_AES_CBC_PAD_INSERT => CK_AES_CBC_PAD_INSERT_PARAMS,
      CKM_AES_CBC_PAD_EXTRACT_FLATTENED => CK_AES_CBC_PAD_EXTRACT_PARAMS,
      CKM_AES_CBC_PAD_INSERT_FLATTENED => CK_AES_CBC_PAD_INSERT_PARAMS,
      CKM_PKCS5_PBKD2 => Luna::CK_PKCS5_PBKD2_PARAMS
    }

    # Path and file name of the loaded cryptoki library.
    attr_reader :so_path

    # Load and initialize a pkcs11 dynamic library with Safenet Luna extensions.
    #
    # Set +so_path+ to +:config+, in order to autodetect the .dll or .so or
    # set it to the full path of the .dll or .so file.
    #
    # @param [String, Symbol] so_path  Shortcut-Symbol or path to the *.so or *.dll file to load.
    # @param [Hash, CK_C_INITIALIZE_ARGS] args  A Hash or CK_C_INITIALIZE_ARGS instance with load params.
    #
    # See also PKCS11::Library#initialize[http://pkcs11.rubyforge.org/pkcs11/PKCS11/Library.html#initialize-instance_method] of pkcs11.gem
    alias unwrapped_initialize initialize 
    def initialize(so_path = :config, args = {})
      unwrapped_initialize(so_path, args)
    end

    def load_library(so_path)
      @so_path = resolve_so_path(so_path)
      super(@so_path)
    end
    
    def resolve_so_path(so_path)
      if so_path == :config
        if RUBY_PLATFORM =~ /mswin|mingw/
          config_file = File.join(ENV['ChrystokiConfigurationPath'], 'crystoki.ini')
          config_content = File.read(config_file)
          config_content.scan(/\[Chrystoki2\](.*?)\[/m) do |crystoki2|
            section = $1
            lib = 'LibNT'
            section.scan(/#{lib}\s*=\s*(.*)/) do |lib_path|
              return $1
            end 
          end
          so_path = "C:\\Program Files\\SafeNet\\LunaClient\\win32\\cryptoki.dll"
        else
          config_content = File.read('/etc/Chrystoki.conf')
          config_content.scan(/Chrystoki2.*?\{(.*?)\}/m) do |crystoki2|
            section = $1
            lib = if ['a'].pack("p").size == 8 then 'LibUNIX64' else 'LibUNIX' end
            section.scan(/#{lib}\s*=\s*(.*);/) do |lib_path|
              return $1
            end
          end
          so_path = '/usr/lib/libCryptoki2_64.so'
        end
      end
      so_path
    end
      
    private :resolve_so_path

   
    def vendor_const_get(name)
      return Luna.const_get(name) if Luna.const_defined?(name)
      super
    end

    def vendor_all_attribute_names
      return Luna::ATTRIBUTES.values + super
    end

    def vendor_mechanism_parameter_struct(mech)
      MechanismParameters[mech] || super
    end

    def vendor_raise_on_return_value(rv)
      if ex=PKCS11::RETURN_VALUES[rv]
        raise(ex, rv.to_s)
      end
      if ex=Luna::RETURN_VALUES[rv]
        raise(ex, rv.to_s)
      end
      super
    end

    def vendor_class_CK_ATTRIBUTE
      Luna::CK_ATTRIBUTE
    end
  end
  
end
end
