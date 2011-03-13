module PKCS11
  # A Library instance holds a handle to the opened PKCS#11 - dll or so file.
  #
  # == Low layer API
  # The API of the binding consists of a lower layer, which
  # is near to the PKCS#11 C interface, and a higher layer, which
  # is more Ruby like and more comfortable. The low layer is currently
  # not explicitly documented and is not recommented to use.
  #
  # All low layer PKCS#11 functions can be called on the {PKCS11::Library} object.
  # Example for starting a session:
  #   pkcs11 = PKCS11.open("/path/to/pkcs11.so")
  #   slot = pkcs11.C_GetSlotList(true).first
  #   session = pkcs11.C_OpenSession(slot, PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION)
  #   pkcs11.C_Login(session, PKCS11::CKU_USER, "password")
  #
  # The same on the high layer:
  #   pkcs11 = PKCS11.open("/path/to/pkcs11.so")
  #   session = pkcs11.active_slots.first.open
  #   session.login(:USER, "password")
  class Library
    # @private
    alias unwrapped_initialize initialize # :nodoc:

    # Load and initialize a pkcs11 dynamic library.
    #
    # @param [String, nil] so_path  Path to the *.so or *.dll file to load.
    # @param [Hash, CK_C_INITIALIZE_ARGS] args  A Hash or CK_C_INITIALIZE_ARGS instance with load params.
    #
    # If so_path is +nil+ no library is loaded or initialized.
    # In this case the calls to {#load_library}, {#C_GetFunctionList} and
    # {#C_Initialize} have to be done manually, before using other methods:
    #   pkcs11 = PKCS11::Library.new
    #   pkcs11.load_library(so_path)
    #   pkcs11.C_GetFunctionList
    #   pkcs11.C_Initialize(args)
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
    # @return [CK_INFO]
    def C_GetInfo
      unwrapped_C_GetInfo
    end
    alias info C_GetInfo

    alias unwrapped_C_GetSlotList C_GetSlotList

    # Obtain an array of Slot objects in the system.
    #
    # @param [true, false] tokenPresent  indicates whether the list
    #    obtained includes only those slots with a token present (true), or
    #    all slots (false);
    # @return [Array<Slot>]
    def C_GetSlotList(tokenPresent=true)
      slots = unwrapped_C_GetSlotList(tokenPresent)
      slots.map{|slot|
        Slot.new self, slot
      }
    end
    alias slots C_GetSlotList

    # Obtain an array of Slot objects in the system with a token present.
    # @return [Array<Slot>]
    def active_slots
      slots(true)
    end

    # Obtain an array of Slot objects in the system regardless if a token is present.
    # @return [Array<Slot>]
    def all_slots
      slots(false)
    end

    # Finalize and unload the library. If not called explicit, the library is freed by the GC.
    def close
      self.C_Finalize
      self.unload_library
    end

    # Return the value of a named constant. Used for CKA_* and CKM_* .
    # This method could be overloaded for vendor specific extensions.
    #
    # @param [String] name Name of the constant
    # @return [Integer] Value of the constant
    def pkcs11_const_get(name) # :nodoc:
      PKCS11.const_get(name)
    end

    # Return the parameter struct of a given mechanism.
    # This method could be overloaded for vendor specific extensions.
    #
    # @param [Integer] mech Mechanism
    # @return [PKCS11::CStruct] appropriate class as parameter for the mechanism
    def pkcs11_mechanism_parameter_struct(mech) # :nodoc:
      Helper::MechanismParameters[mech]
    end

    private :unwrapped_initialize
    private :unwrapped_C_GetSlotList
    private :unwrapped_C_GetInfo
  end
end
