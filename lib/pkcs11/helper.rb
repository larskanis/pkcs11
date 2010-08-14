module PKCS11
  # Some functions internaly used to make the API more convenient.
  module Helper  # :nodoc:
    private
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
          PKCS11::CK_MECHANISM.new(string_to_handle('CKM_', mechanism.keys.first), mechanism.values.first)
        when Fixnum
          PKCS11::CK_MECHANISM.new(mechanism)
        else
          mechanism
      end
    end
  end
end
