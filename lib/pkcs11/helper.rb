module PKCS11
  # Some functions internaly used to make the API more convenient.
  module Helper  # :nodoc:
    private

    MechanismParameters = {
      CKM_RSA_PKCS_OAEP => CK_RSA_PKCS_OAEP_PARAMS,
      CKM_RSA_PKCS_PSS => CK_RSA_PKCS_PSS_PARAMS,
      CKM_SHA1_RSA_PKCS_PSS => CK_RSA_PKCS_PSS_PARAMS,
      CKM_SHA256_RSA_PKCS_PSS => CK_RSA_PKCS_PSS_PARAMS,
      CKM_SHA384_RSA_PKCS_PSS => CK_RSA_PKCS_PSS_PARAMS,
      CKM_SHA512_RSA_PKCS_PSS => CK_RSA_PKCS_PSS_PARAMS,
      CKM_ECDH1_DERIVE => CK_ECDH1_DERIVE_PARAMS,
      CKM_ECDH1_COFACTOR_DERIVE => CK_ECDH1_DERIVE_PARAMS,

      CKM_DES_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_DES_CBC_ENCRYPT_DATA => CK_DES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_DES3_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_DES3_CBC_ENCRYPT_DATA => CK_DES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_AES_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_AES_CBC_ENCRYPT_DATA => CK_AES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_CONCATENATE_BASE_AND_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_CONCATENATE_DATA_AND_BASE => CK_KEY_DERIVATION_STRING_DATA,
      CKM_XOR_BASE_AND_DATA => CK_KEY_DERIVATION_STRING_DATA,
    }

    def to_attributes(template)
      case template
        when Array
          template.map{|v| PKCS11::CK_ATTRIBUTE.new(string_to_handle('CKA_', v), nil) }
        when Hash
          template.map{|k,v| PKCS11::CK_ATTRIBUTE.new(string_to_handle('CKA_', k), v) }
        when String, Symbol
          [PKCS11::CK_ATTRIBUTE.new(string_to_handle('CKA_', template), nil)]
        when Integer
          [PKCS11::CK_ATTRIBUTE.new(template, nil)]
        else
          template
      end
    end

    def string_to_handle(prefix, attribute) # :nodoc:
      case attribute
        when String, Symbol
          PKCS11.const_get("#{prefix}#{attribute}")
        else
          attribute
      end
    end

    def to_mechanism(mechanism) # :nodoc:
      case mechanism
        when String, Symbol
          PKCS11::CK_MECHANISM.new(string_to_handle('CKM_', mechanism))
        when Hash
          raise "only one mechanism allowed" unless mechanism.length==1

          mech = string_to_handle('CKM_', mechanism.keys.first)
          param = mechanism.values.first
          case param
          when Hash
            param_class = MechanismParameters[mech]
            raise ArgumentError, "unknown mechanism - please use mechanism parameter as String" unless param_class
            
            pa = param_class.new
            param.each do |k, v|
              pa.send "#{k}=", v
            end
            param = pa
          end
          
          PKCS11::CK_MECHANISM.new(mech, param)
        when Fixnum
          PKCS11::CK_MECHANISM.new(mechanism)
        else
          mechanism
      end
    end
  end
end
