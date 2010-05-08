require 'pkcs11/slot'
require 'pkcs11/session'
require 'pkcs11/object'

# Ruby connector to PKCS#11 libraries.
#
# This library allowes to use PKCS#11 librarys in Ruby MRI.
#
# Example usage:
#
#   pkcs11 = PKCS11.new("/path/to/pkcs11.so")
#   slot = pkcs11.active_slots.first
#   p slot.info
#   session = slot.open(PKCS11::CKF_SERIAL_SESSION|PKCS11::CKF_RW_SESSION)
#   session.login(:USER, "1234")
#   ...
#   session.logout
#   session.close
#
# See unit tests in the <tt>test</tt> directory for further examples of the usage.
class PKCS11
  alias unwrapped_initialize initialize # :nodoc:
  private :unwrapped_initialize

  # Load and initialize a pkcs11 dynamic library.
  #
  # * <tt>so_path</tt> : Path to the *.so or *.dll file to load.
  # * <tt>args</tt> : A Hash or CK_C_INITIALIZE_ARGS instance with load params.
  def initialize(so_path, args={})
    case args
      when Hash
        pargs = CK_C_INITIALIZE_ARGS.new
        args.each{|k,v| pargs.send("#{k}=", v) }
      else
        pargs = args
    end
    unwrapped_initialize(so_path, pargs)
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
    include InspectableStruct
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

  alias info C_GetInfo
  
  alias unwrapped_C_GetSlotList C_GetSlotList
  private :unwrapped_C_GetSlotList
  
  # Obtain an array of Slot objects in the system. tokenPresent indicates
  # whether the list obtained includes only those slots with a token present (true), or
  # all slots (false);
  def C_GetSlotList(tokenPresent=true)
    slots = unwrapped_C_GetSlotList(tokenPresent)
    slots.map{|slot|
      Slot.new self, slot
    }
  end
  alias slots C_GetSlotList
  
  # Obtain an array of Slot objects in the system with a token present.
  def active_slots
    slots(true)
  end
  # Obtain an array of Slot objects in the system regardless if a token is present.
  def all_slots
    slots(false)
  end
  
end
