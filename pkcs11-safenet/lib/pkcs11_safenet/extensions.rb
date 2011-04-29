#!/usr/bin/env ruby

module PKCS11
module Safenet
  # Derive CK_ATTRIBUTE to get converted attributes.
  class CK_ATTRIBUTE < PKCS11::CK_ATTRIBUTE
    ATTRIBUTES = {
      CKA_EXPORT => :bool,
      CKA_EXPORTABLE => :bool,
      CKA_TRUSTED => :bool,
      CKA_DELETABLE => :bool,
      CKA_SIGN_LOCAL_CERT => :bool,
      CKA_IMPORT => :bool,
      CKA_USAGE_COUNT => :ulong,
      CKA_KEY_SIZE => :ulong,
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

  # A Safenet::Library instance holds a handle to the opened +cryptoki.dll+ or +cryptoki.so+ file.
  #
  # This class is derived from
  # PKCS11::Library[http://pkcs11.rubyforge.org/pkcs11/PKCS11/Library.html] of pkcs11.gem.
  class Library < PKCS11::Library
    MechanismParameters = {
      CKM_DES_DERIVE_CBC => CK_DES_CBC_PARAMS,
      CKM_DES3_DERIVE_CBC => CK_DES3_CBC_PARAMS,
      CKM_ECIES => CK_ECIES_PARAMS,
      CKM_ENCODE_X_509 => CK_MECH_TYPE_AND_OBJECT,
      CKM_PKCS12_PBE_EXPORT => CK_PKCS12_PBE_EXPORT_PARAMS,
      CKM_PKCS12_PBE_IMPORT => CK_PKCS12_PBE_IMPORT_PARAMS,
      CKM_PP_LOAD_SECRET => CK_PP_LOAD_SECRET_PARAMS,
      CKM_REPLICATE_TOKEN_RSA_AES => CK_REPLICATE_TOKEN_PARAMS,
      CKM_SECRET_RECOVER_WITH_ATTRIBUTES => CK_SECRET_SHARE_PARAMS,
      CKM_SHA1_RSA_PKCS_TIMESTAMP => CK_TIMESTAMP_PARAMS,
    }

    # Path and file name of the loaded cryptoki library.
    attr_reader :so_path

    # Load and initialize a pkcs11 dynamic library with Safenet Protect Server extensions.
    #
    # Set +so_path+ to +:hsm+, +:sw+ or +:logger+ in order to autodetect the cryptoki-HSM or
    # software emulation library file.
    #
    # @param [String, Symbol, nil] so_path  Shortcut-Symbol or path to the *.so or *.dll file to load.
    # @param [Hash, CK_C_INITIALIZE_ARGS] args  A Hash or CK_C_INITIALIZE_ARGS instance with load params.
    #
    # See also PKCS11::Library#initialize[http://pkcs11.rubyforge.org/pkcs11/PKCS11/Library.html#initialize-instance_method] of pkcs11.gem
    def initialize(so_path = nil, args = {})
      if [:sw, :hsm].include?(so_path)
        if RUBY_PLATFORM =~ /mswin|mingw/
          libctsw_so = "cryptoki.dll"
          libctsw_so_paths = [
            File.join(ENV['ProgramFiles'], "SafeNet/ProtectToolkit C SDK/bin/#{so_path}"),
          ]
        else
          libctsw_so = "libct#{so_path}.so"
          libctsw_so_paths = [
            "/opt/ETcpsdk/lib/linux-i386",
            "/opt/PTK/lib",
          ]
        end

        unless so_path=ENV['CRYPTOKI_SO']
          paths = libctsw_so_paths.collect{|path| File.join(path, libctsw_so) }
          so_path = paths.find{|path| File.exist?(path) }
        end

        raise "#{libctsw_so} not found - please install Safenet PTK-C or set ENV['CRYPTOKI_SO']" unless so_path
      end

      @so_path = so_path
      super(so_path, args)
    end

    def vendor_const_get(name)
      return Safenet.const_get(name) if Safenet.const_defined?(name)
      super
    end

    def vendor_mechanism_parameter_struct(mech)
      MechanismParameters[mech] || super
    end

    def vendor_raise_on_return_value(rv)
      if ex=Safenet::RETURN_VALUES[rv]
        raise(ex, rv.to_s)
      end
      super
    end

    def vendor_class_CK_ATTRIBUTE
      Safenet::CK_ATTRIBUTE
    end
  end
end
end
