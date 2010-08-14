require 'pkcs11/helper'

module PKCS11
  # Cryptoki’s logical view of a token is a device that stores objects and can perform
  # cryptographic functions. Cryptoki defines three classes of object: data, certificates, and
  # keys.
  #
  # Attributes are characteristics that distinguish an instance of an object.
  class Object
    include Helper

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
    # attribute:: can be String or Symbol of the attribute constant
    #             or the attribute number as Integer.
    #
    # Returns the attribute value as String, Integer or true/false
    # depending on the attribute type.
    # Unknown attributes (out of PKCS#11 v2.2) are not converted but returned as String.
    # That is true/false will be returned as "\\001" respectively "\\000".
    def [](attribute)
      attrs = C_GetAttributeValue( [attribute] )
      attrs.first.value unless attrs.empty?
    end

    # Modifies the value of one attribute the object.
    #
    # attribute:: can be String or Symbol of the attribute constant
    #             or the attribute value as Integer.
    # value:: String value the attribute will be set to.
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
    #   object.attributes = {:SUBJECT => cert_subject, PKCS11::CKA_VALUE => cert_data}
    def C_SetAttributeValue(template={})
      template = to_attributes template
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
      template = to_attributes template
      @pk.C_GetAttributeValue(@sess, @obj, template)
    end
    alias attributes C_GetAttributeValue

    # Copies an object, creating a new object for the copy.
    #
    # The template may specify new values for any attributes of the object that can ordinarily
    # be modified (e.g., in the course of copying a secret key, a key’s CKA_EXTRACTABLE
    # attribute may be changed from true to false, but not the other way around.
    # If this change is made, the new key’s CKA_NEVER_EXTRACTABLE attribute will
    # have the value false. Similarly, the template may specify that the new key’s
    # CKA_SENSITIVE attribute be true; the new key will have the same value for its
    # CKA_ALWAYS_SENSITIVE attribute as the original key). It may also specify new
    # values of the CKA_TOKEN and CKA_PRIVATE attributes (e.g., to copy a session
    # object to a token object). If the template specifies a value of an attribute which is
    # incompatible with other existing attributes of the object, the call fails exception
    # CKR_TEMPLATE_INCONSISTENT.
    #
    # Only session objects can be created during a read-only session. Only public objects can
    # be created unless the normal user is logged in.
    def C_CopyObject(template={})
      handle = @pk.C_CopyObject(@sess, @obj, to_attributes(template))
      Object.new @pk, @sess, handle
    end
    alias copy C_CopyObject

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
