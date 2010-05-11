module PKCS11
  class Object
    def initialize(pkcs11, session, object) # :nodoc:
      @pk, @sess, @obj = pkcs11, session, object
    end

    # The object handle.
    def to_int
      @obj
    end
    alias to_i to_int

    def inspect # :nodoc:
      "#<#{self.class} #{@obj.inspect}>"
    end

    # Returns the value of one attribute of the object.
    #
    # * <tt>attribute</tt> : can be String or Symbol of the attribute constant
    # or the attribute number as Integer.
    #
    # Returns the attribute value as String. No conversations are carried out.
    # That is true/false will be returned as "\001" respectively "\000".
    def [](attribute)
      attrs = C_GetAttributeValue( [attribute] )
      attrs.first.value unless attrs.empty?
    end

    # Modifies the value of one attribute the object.
    #
    # * <tt>attribute</tt> : can be String or Symbol of the attribute constant
    # or the attribute value as Integer.
    # * <tt>value</tt> : String value the attribute will be set to.
    #
    # Following value conversations are done:
    #   true   -> 0x01
    #   false  -> 0x00
    #   nil    -> NULL pointer
    #   Fixnum -> binary encoded unsigned long
    def []=(attribute, value)
      C_SetAttributeValue( attribute => value )
    end

    # Modifies the value of one or more attributes of the object in a single call.
    #
    # Examples:
    #   object.attributes = :SUBJECT => cert_subject, PKCS11::CKA_VALUE => cert_data
    def C_SetAttributeValue(template={})
      template = Session.hash_to_attributes template
      @pk.C_SetAttributeValue(@sess, @obj, template)
    end
    alias attributes= C_SetAttributeValue
    
    # Obtains the value of one or more attributes of the object in a single call.
    #
    # Without params all known attributes are tried to read from the Object.
    # This is significant slower then naming the needed attributes and should
    # be used for debug purposes only.
    #
    # Returns an Array of PKCS11::CK_ATTRIBUTE's.
    #
    # Example:
    #   certificate.attributes :ID, :VALUE
    def C_GetAttributeValue(*template)
      case template.length
        when 0
          return PKCS11::ATTRIBUTES.values.map{|attr|
            begin
              attributes(PKCS11.const_get(attr))
            rescue PKCS11::Error
            end
          }.flatten.compact
        when 1
          template = template[0]
      end
      template = Session.hash_to_attributes template
      @pk.C_GetAttributeValue(@sess, @obj, template)
    end
    alias attributes C_GetAttributeValue
    
    # Destroys the object.
    #
    # Only session objects can be destroyed during a read-only session. Only public objects
    # can be destroyed unless the normal user is logged in.
    def C_DestroyObject()
      @pk.C_DestroyObject(@sess, @obj)
    end
    alias destroy C_DestroyObject
    
    # Gets the size of an object in bytes.
    def C_GetObjectSize()
      @pk.C_GetObjectSize(@sess, @obj)
    end
    alias size C_GetObjectSize

  end
end
