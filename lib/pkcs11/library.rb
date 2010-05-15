module PKCS11
  class Library
    alias unwrapped_initialize initialize # :nodoc:

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

    alias unwrapped_C_GetInfo C_GetInfo
    # Returns general information about Cryptoki.
    def C_GetInfo
      unwrapped_C_GetInfo
    end
    alias info C_GetInfo

    alias unwrapped_C_GetSlotList C_GetSlotList
    
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
    
    alias unwrapped_C_Finalize C_Finalize
    # Close and unload library. If not called, the library is freed by the GC.
    def C_Finalize
      unwrapped_C_Finalize
    end
    alias close C_Finalize
    
    private :unwrapped_initialize
    private :unwrapped_C_GetSlotList
    private :unwrapped_C_Finalize
    private :unwrapped_C_GetInfo
  end
end
