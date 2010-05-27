require 'pkcs11/library'
require 'pkcs11/slot'
require 'pkcs11/session'
require 'pkcs11/object'

# Ruby connector to PKCS#11 libraries.
#
# This library allowes to use PKCS#11 librarys in Ruby MRI.
#
# Example usage:
#
#   pkcs11 = PKCS11.open("/path/to/pkcs11.so")
#   slot = pkcs11.active_slots.first
#   p slot.info
#   session = slot.open(PKCS11::CKF_SERIAL_SESSION|PKCS11::CKF_RW_SESSION)
#   session.login(:USER, "1234")
#   ...
#   session.logout
#   session.close
#
# See unit tests in the <tt>test</tt> directory for further examples of the usage.
module PKCS11

  class << self
  # Open a PKCS#11 library file.
  alias new open
  end
  
  module InspectableStruct
    # Array of the InspectableStruct's attribute names.
    def members
      (self.methods - ::Object.new.methods - InspectableStruct.instance_methods).grep(/[^=]$/).sort
    end
    # Array of the InspectableStruct's attribute values.
    def values
      members.inject([]){|a,v| a << send(v) }
    end
    # Hash with the InspectableStruct's attribute names and values.
    def to_hash
      members.inject({}){|h,v| h[v.intern] = send(v); h }
    end
    def inspect # :nodoc:
      "#<#{self.class} #{to_hash.map{|k,v| "#{k}=#{v.inspect}"}.join(", ") }>"
    end
  end

  module InspectableAttribute
    # Array of the InspectableStruct's attribute names.
    def members
      ['type', 'value']
    end
    # Array of the InspectableStruct's attribute values.
    def values
      members.inject([]){|a,v| a << send(v) }
    end
    # Hash with the InspectableStruct's attribute names and values.
    def to_hash
      members.inject({}){|h,v| h[v.intern] = send(v); h }
    end
    # Get the constant name as String of the given value.
    # Returns <tt>nil</tt> if value is unknown.
    def to_s
      ATTRIBUTES[type]
    end
    def inspect # :nodoc:
      "#<#{self.class} #{ to_s ? "#{to_s} (#{type})" : type} value=#{value.inspect}>"
    end
  end

  # See InspectableStruct.
  class CK_INFO
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_C_INITIALIZE_ARGS
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_ATTRIBUTE
    include InspectableAttribute
  end
  # See InspectableStruct.
  class CK_TOKEN_INFO
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_SLOT_INFO
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_MECHANISM_INFO
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_SESSION_INFO
    include InspectableStruct
  end
  # See InspectableStruct.
  class CK_MECHANISM
    include InspectableStruct
  end

  class ConstValue
    def initialize(enum_hash, value) # :nodoc:
      @enum_hash, @value = enum_hash, value
    end

    # Get the constant name as String of the given value.
    # Returns <tt>nil</tt> if value is unknown.
    def to_s
      @enum_hash[@value]
    end
    def inspect
#       "#<#{self.class} #{ to_s ? "#{to_s} (#{@value})" : @value}>"
      @value.inspect
    end

    # The value of the constant.
    def to_int
      @value
    end
    alias to_i to_int
  end

  module ConstValueHash # :nodoc:
    def [](value)
      super(value.to_int)
    end
  end

  class << self
    def extend_ConstValueHash(hash_symb) # :nodoc:
      # The MECHANISMS, ATTRIBUTES, etc. Hashs are freezed.
      # So, we have make a copy, to extend the class.
      my_HASH = const_get(hash_symb).dup
      my_HASH.extend ConstValueHash
      my_HASH.freeze
      const_set("UNWRAPPED_#{hash_symb}", hash_symb)
      remove_const(hash_symb)
      const_set(hash_symb, my_HASH)
    end
    private :extend_ConstValueHash
  end

  extend_ConstValueHash(:OBJECT_CLASSES)
  class ObjectClass < ConstValue
  end

  extend_ConstValueHash(:ATTRIBUTES)
  class Attribute < ConstValue
  end

  extend_ConstValueHash(:MECHANISMS)
  class Mechanism < ConstValue
  end

#   extend_ConstValueHash(:RETURN_VALUES)
#   class ReturnValue < ConstValue
#   end
end
