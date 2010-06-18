module PKCS11
  # A Library instance holds a handle to the opened PKCS#11 - dll or so file.
  class Library
    alias unwrapped_initialize initialize # :nodoc:

    # Load and initialize a pkcs11 dynamic library.
    #
    # so_path:: Path to the *.so or *.dll file to load.
    # args:: A Hash or CK_C_INITIALIZE_ARGS instance with load params.
    def initialize(so_path=nil, args={})
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

    # Finalize and unload the library. If not called, the library is freed by the GC.
    def close
      self.C_Finalize
      self.unload_library
    end
    
    private :unwrapped_initialize
    private :unwrapped_C_GetSlotList
    private :unwrapped_C_GetInfo
  end
end
