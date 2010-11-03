require 'pkcs11/library'
require 'pkcs11/slot'
require 'pkcs11/session'
require 'pkcs11/object'

# Ruby connector to PKCS#11 libraries.
#
# This library allowes to use PKCS#11 librarys in Ruby MRI.
#
# @example
#   pkcs11 = PKCS11.open("/path/to/pkcs11.so")
#   slot = pkcs11.active_slots.first
#   p slot.info
#   session = slot.open(PKCS11::CKF_SERIAL_SESSION|PKCS11::CKF_RW_SESSION)
#   session.login(:USER, "1234")
#   # ... crypto operations
#   session.logout
#   session.close
#
# See unit tests in the <tt>test</tt> directory for further examples of the usage.
module PKCS11

  class << self
    # Open a PKCS#11 library file.
    alias new open
  end

  # Base class of all PKCS#11 structs.
  class CStruct
    # @return [Array<String>] attribute names
    def values
      members.inject([]){|a,v| a << send(v) }
    end
    # @return [Hash] with attribute names and current values
    def to_hash
      members.inject({}){|h,v| h[v.intern] = send(v); h }
    end
    def inspect
      "#<#{self.class} #{to_hash.map{|k,v| "#{k}=#{v.inspect}"}.join(", ") }>"
    end
  end

  # Struct to hold an attribute type and it's value.
  #
  # @see PKCS11::Object
  class CK_ATTRIBUTE
    # @return [Array<String>] attribute names
    def members
      ['type', 'value']
    end
    # @return [Array<String, Boolean, Integer>] attribute values
    def values
      members.inject([]){|a,v| a << send(v) }
    end
    # @return [Hash] with attribute names and current values
    def to_hash
      members.inject({}){|h,v| h[v.intern] = send(v); h }
    end
    # Get the constant name as String of the given value.
    # @return [String, nil]  Returns <tt>nil</tt> if value is unknown
    def to_s
      ATTRIBUTES[type]
    end
    def inspect
      "#<#{self.class} #{ to_s ? "#{to_s} (#{type})" : type} value=#{value.inspect}>"
    end
  end
end
