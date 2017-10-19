module PKCS11
  # Some functions internaly used to make the API more convenient.
  # @private
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
      CKM_ECMQV_DERIVE => CK_ECMQV_DERIVE_PARAMS,
      CKM_X9_42_DH_DERIVE => CK_X9_42_DH1_DERIVE_PARAMS,
# 			CKM_X9_42_MQV_DERIVE => CK_X9_42_DH2_DERIVE_PARAMS,
      CKM_X9_42_DH_HYBRID_DERIVE => CK_X9_42_DH2_DERIVE_PARAMS,
      CKM_X9_42_MQV_DERIVE => CK_X9_42_MQV_DERIVE_PARAMS,
      CKM_KEA_KEY_DERIVE => CK_KEA_DERIVE_PARAMS,
      CKM_RC2_CBC => CK_RC2_CBC_PARAMS,
      CKM_RC2_CBC_PAD => CK_RC2_CBC_PARAMS,
      CKM_RC2_MAC_GENERAL => CK_RC2_MAC_GENERAL_PARAMS,
      CKM_RC5_MAC => CK_RC5_PARAMS,
      CKM_RC5_ECB => CK_RC5_PARAMS,
      CKM_RC5_CBC => CK_RC5_CBC_PARAMS,
      CKM_RC5_CBC_PAD => CK_RC5_CBC_PARAMS,
      CKM_RC5_MAC_GENERAL => CK_RC5_MAC_GENERAL_PARAMS,

      CKM_SKIPJACK_PRIVATE_WRAP => CK_SKIPJACK_PRIVATE_WRAP_PARAMS,
      CKM_SKIPJACK_RELAYX => CK_SKIPJACK_RELAYX_PARAMS,
      CKM_PBE_MD2_DES_CBC => CK_PBE_PARAMS,
      CKM_PBE_MD5_DES_CBC => CK_PBE_PARAMS,
      CKM_PBE_MD5_CAST_CBC => CK_PBE_PARAMS,
      CKM_PBE_MD5_CAST3_CBC => CK_PBE_PARAMS,
      CKM_PBE_MD5_CAST5_CBC => CK_PBE_PARAMS,
      CKM_PBE_MD5_CAST128_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_CAST5_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_CAST128_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_RC4_128 => CK_PBE_PARAMS,
      CKM_PBE_SHA1_RC4_40 => CK_PBE_PARAMS,
      CKM_PBE_SHA1_DES3_EDE_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_DES2_EDE_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_RC2_128_CBC => CK_PBE_PARAMS,
      CKM_PBE_SHA1_RC2_40_CBC => CK_PBE_PARAMS,
      CKM_PBA_SHA1_WITH_SHA1_HMAC => CK_PBE_PARAMS,
      CKM_PKCS5_PBKD2 => CK_PKCS5_PBKD2_PARAMS,
      CKM_KEY_WRAP_SET_OAEP => CK_KEY_WRAP_SET_OAEP_PARAMS,
      CKM_SSL3_MASTER_KEY_DERIVE => CK_SSL3_RANDOM_DATA,
      CKM_SSL3_KEY_AND_MAC_DERIVE => CK_SSL3_RANDOM_DATA,
      CKM_SSL3_MASTER_KEY_DERIVE => CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
      CKM_SSL3_KEY_AND_MAC_DERIVE => CK_SSL3_KEY_MAT_OUT,
      CKM_SSL3_KEY_AND_MAC_DERIVE => CK_SSL3_KEY_MAT_PARAMS,
      CKM_TLS_MASTER_KEY_DERIVE => CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
      CKM_TLS_MAC => CK_TLS_MAC_PARAMS,
      CKM_TLS_KDF => CK_TLS_KDF_PARAMS,
      CKM_WTLS_MASTER_KEY_DERIVE => CK_WTLS_RANDOM_DATA,
      CKM_WTLS_MASTER_KEY_DERIVE => CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
      CKM_WTLS_PRF => CK_WTLS_PRF_PARAMS,
      CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE => CK_WTLS_KEY_MAT_PARAMS,
      CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE => CK_WTLS_KEY_MAT_PARAMS,
      CKM_CMS_SIG => CK_CMS_SIG_PARAMS,

      CKM_DES_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_DES_CBC_ENCRYPT_DATA => CK_DES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_DES3_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_DES3_CBC_ENCRYPT_DATA => CK_DES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_AES_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_AES_CBC_ENCRYPT_DATA => CK_AES_CBC_ENCRYPT_DATA_PARAMS,
      CKM_CONCATENATE_BASE_AND_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_CONCATENATE_DATA_AND_BASE => CK_KEY_DERIVATION_STRING_DATA,
      CKM_XOR_BASE_AND_DATA => CK_KEY_DERIVATION_STRING_DATA,

      CKM_ARIA_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_ARIA_CBC_ENCRYPT_DATA => CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,

      CKM_SSL3_PRE_MASTER_KEY_GEN => CK_VERSION,
      CKM_TLS_PRE_MASTER_KEY_GEN => CK_VERSION,
=begin
      # for PKCS#11 v2.30
      CKM_SEED_ECB_ENCRYPT_DATA => CK_KEY_DERIVATION_STRING_DATA,
      CKM_SEED_CBC_ENCRYPT_DATA => CK_CBC_ENCRYPT_DATA_PARAMS,
      CKM_GOSTR3410_KEY_WRAP => CK_GOSTR3410_KEY_WRAP_PARAMS,
      CKM_GOSTR3410_DERIVE => CK_GOSTR3410_DERIVE_PARAMS,
      CKM_GOSTR3410_KEY_WRAP => CK_GOSTR3410_KEY_WRAP_PARAMS,
=end
    }

    def to_attributes(template)
      case template
        when Array
          template.map{|v| @pk.vendor_class_CK_ATTRIBUTE.new(string_to_handle('CKA_', v), nil) }
        when Hash
          template.map{|k,v| @pk.vendor_class_CK_ATTRIBUTE.new(string_to_handle('CKA_', k), v) }
        when String, Symbol
          [@pk.vendor_class_CK_ATTRIBUTE.new(string_to_handle('CKA_', template), nil)]
        when Integer
          [@pk.vendor_class_CK_ATTRIBUTE.new(template, nil)]
        else
          template
      end
    end

    def string_to_handle(prefix, attribute) # :nodoc:
      case attribute
        when String, Symbol
          @pk.vendor_const_get("#{prefix}#{attribute}")
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
            param_class = @pk.vendor_mechanism_parameter_struct(mech)
            raise ArgumentError, "unknown mechanism - please use String/Int/Struct as mechanism parameter" unless param_class

            pa = param_class.new
            param.each do |k, v|
              pa.send "#{k}=", v
            end
            param = pa
          end

          PKCS11::CK_MECHANISM.new(mech, param)
        when Integer
          PKCS11::CK_MECHANISM.new(mechanism)
        else
          mechanism
      end
    end
  end
end
