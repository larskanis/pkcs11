class PKCS11
  class Object
    def initialize(pkcs11, session, object)
      @pk, @sess, @obj = pkcs11, session, object
    end

    # The object handle.
    def to_int
      @obj
    end
    alias to_i to_int

    def inspect
      "#<#{self.class} #{@obj.inspect}>"
    end

    # Returns the value of one attribute the object.
    #
    # attribute can be String or Symbol of the attribute constant
    # or the attribute value as Integer.
    def [](attribute)
      attrs = C_GetAttributeValue( [attribute] )
      attrs.first.value unless attrs.empty?
    end

    # Modifies the value of one attribute the object.
    def []=(attribute, value)
      C_SetAttributeValue( attribute => value )
    end

    # Modifies the value of one or more attributes the object.
    #
    # Examples:
    #   object.attributes = :VALUE => cert_data
    #   object.attributes = PKCS11::CKA_VALUE => cert_data
    def C_SetAttributeValue(template={})
      template = Session.hash_to_attributes template
      @pk.C_SetAttributeValue(@sess, @obj, template)
    end
    alias attributes= C_SetAttributeValue
    
    # Obtains the value of one or more attributes the object.
    # Returns an Array of PKCS11::CK_ATTRIBUTE.
    #
    # Example:
    #   p object.attributes [:ID, :VALUE]
    def C_GetAttributeValue(template={})
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
