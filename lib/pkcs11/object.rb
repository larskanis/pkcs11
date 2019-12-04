require 'pkcs11/helper'

module PKCS11
  # Cryptoki's logical view of a token is a device that stores objects and can perform
  # cryptographic functions. Cryptoki defines three classes of object: data, certificates, and
  # keys.
  #
  # Attributes are characteristics that distinguish an instance of an object.
  class Object
    include Helper

    # @private
    def initialize(pkcs11, session, object) # :nodoc:
      @pk, @sess, @obj = pkcs11, session, object
    end

    # The object handle.
    # @return [Integer]
    def to_int
      @obj
    end
    alias to_i to_int

    # @private
    def inspect # :nodoc:
      "#<#{self.class} #{@obj.inspect}>"
    end

    # Get the value of one or several attributes of the object.
    #
    # @param [String, Symbol, Integer, Array] attribute can be String or Symbol
    #             of the attribute(s) constant or the attribute(s) number as Integer.
    #
    # @return [String, Integer, Boolean, Array, nil] the attribute value as String,
    #   Integer or true/false depending on the attribute type.
    #   If called with more than one parameter or with an Array, a Array
    #   of attribute values is returned.
    # Unknown attributes (out of PKCS#11 v2.2) are not converted to adequate
    # ruby objects but returned as String.
    # That is true/false will be returned as "\\001" respectively "\\000".
    #
    # @example
    #     object[:VALUE] # => "\000\000\000\000\000\000\000\000"
    #     object[:MODULUS_BITS] # => 768
    #     object[:MODULUS_BITS, :LABEL] # => [1024, "MyKey"]
    #
    # See PKCS#11 for attribute definitions.
    def [](*attributes)
      attrs = C_GetAttributeValue( attributes.flatten )
      if attrs.length>1 || attributes.first.kind_of?(Array)
        attrs.map(&:value)
      else
        attrs.first.value unless attrs.empty?
      end
    end

    # Modifies the value of one or several attributes of the object.
    #
    # @param [String, Symbol, Integer] attribute  can be String or Symbol of the attribute constant
    #             or the attribute value as Integer.
    # @param [String, Integer, Boolean, Array, nil] value  value(s) the attribute(s) will be set to.
    #
    # Following value conversations are done from Ruby to C:
    #   true   -> 0x01
    #   false  -> 0x00
    #   nil    -> NULL pointer
    #   Integer-> binary encoded unsigned long
    #
    # @example
    #     object[:VALUE] = "\000\000\000\000\000\000\000\000"
    #     object[:MODULUS_BITS] = 768
    #     object[:MODULUS_BITS, :LABEL] = 1024, 'MyKey'
    #
    # See PKCS#11 for attribute definitions.
    # @return value
    def []=(*attributes)
      values = attributes.pop
      values = [values] unless values.kind_of?(Array)
      raise ArgumentError, "different number of attributes to set (#{attributes.length}) and given values (#{values.length})" unless attributes.length == values.length
      map = values.each.with_index.inject({}){|s, v| s[attributes[v[1]]] = v[0]; s }
      C_SetAttributeValue( map )
    end

    # Modifies the value of one or more attributes of the object in a single call.
    #
    # @example
    #   object.attributes = {SUBJECT:  cert_subject, PKCS11::CKA_VALUE => cert_data}
    # @return template
    def C_SetAttributeValue(template={})
      @pk.C_SetAttributeValue(@sess, @obj, to_attributes(template))
      template
    end
    alias attributes= C_SetAttributeValue

    # Obtains the value of one or more attributes of the object in a single call.
    #
    # @param [Array<String, Symbol, Integer>, Hash, String, Integer] attribute attribute names
    #    whose values should be returned
    #
    # Without params all known attributes are tried to read from the Object.
    # This is significant slower then naming the needed attributes and should
    # be used for debug purposes only.
    #
    # @return [Array<PKCS11::CK_ATTRIBUTE>] Requested attributes with values.
    #
    # @example
    #   certificate.attributes :VALUE, :CLASS
    #    => [#<PKCS11::CK_ATTRIBUTE CKA_VALUE (17) value="0\x82...">, #<PKCS11::CK_ATTRIBUTE CKA_CLASS (0) value=1>]
    def C_GetAttributeValue(*template)
      case template.length
        when 0
          return @pk.vendor_all_attribute_names.map{|attr|
            begin
              attributes(@pk.vendor_const_get(attr))
            rescue PKCS11::Error
            end
          }.flatten.compact
        when 1
          template = template[0]
      end
      template = to_attributes template
      @pk.C_GetAttributeValue(@sess, @obj, template)
    end
    alias attributes C_GetAttributeValue

    # Copies an object, creating a new object for the copy.
    #
    # @param [Hash] template
    #
    # The template may specify new values for any attributes of the object that can ordinarily
    # be modified (e.g., in the course of copying a secret key, a key's CKA_EXTRACTABLE
    # attribute may be changed from true to false, but not the other way around.
    # If this change is made, the new key's CKA_NEVER_EXTRACTABLE attribute will
    # have the value false. Similarly, the template may specify that the new key's
    # CKA_SENSITIVE attribute be true; the new key will have the same value for its
    # CKA_ALWAYS_SENSITIVE attribute as the original key). It may also specify new
    # values of the CKA_TOKEN and CKA_PRIVATE attributes (e.g., to copy a session
    # object to a token object). If the template specifies a value of an attribute which is
    # incompatible with other existing attributes of the object, the call fails with exception
    # CKR_TEMPLATE_INCONSISTENT.
    #
    # Only session objects can be created during a read-only session. Only public objects can
    # be created unless the normal user is logged in.
    #
    # @return [PKCS11::Object] the newly created object
    def C_CopyObject(template={})
      handle = @pk.C_CopyObject(@sess, @obj, to_attributes(template))
      Object.new @pk, @sess, handle
    end
    alias copy C_CopyObject

    # Destroys the object.
    #
    # Only session objects can be destroyed during a read-only session. Only public objects
    # can be destroyed unless the normal user is logged in.
    # @return [PKCS11::Object]
    def C_DestroyObject()
      @pk.C_DestroyObject(@sess, @obj)
      self
    end
    alias destroy C_DestroyObject

    # Gets the size of an object in bytes.
    # @return [Integer]
    def C_GetObjectSize()
      @pk.C_GetObjectSize(@sess, @obj)
    end
    alias size C_GetObjectSize

  end
end
