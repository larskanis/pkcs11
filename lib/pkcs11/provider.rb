module PKCS11
  class Provider
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
end
