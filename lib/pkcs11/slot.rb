class PKCS11
  class Slot
    def initialize(pkcs11, slot)
      @pk, @slot = pkcs11, slot
    end

    def to_int
      @slot
    end
    alias to_i to_int

    def inspect
      "#<#{self.class} #{@slot.inspect}>"
    end

    def C_GetSlotInfo
      @pk.C_GetSlotInfo(@slot)
    end
    alias info C_GetSlotInfo

    def C_GetTokenInfo
      @pk.C_GetTokenInfo(@slot)
    end
    alias token_info C_GetTokenInfo

    def C_WaitForSlotEvent(flags)
      @pk.C_WaitForSlotEvent(@slot, flags)
    end
    alias wait_for_event C_WaitForSlotEvent

    def C_GetMechanismList
      @pk.C_GetMechanismList(@slot).map{|mech|
        Mechanism.new MECHANISMS, mech
      }
    end
    alias mechanisms C_GetMechanismList

    # Obtains information about a particular mechanism possibly
    # supported by a token.
    def C_GetMechanismInfo(mechanism)
      @pk.C_GetMechanismInfo(@slot, mechanism.to_int)
    end
    alias mechanism_info C_GetMechanismInfo

    # Initializes a token. pin is the SO’s initial PIN; label is the label of the token (max 32-byte). This standard allows PIN
    # values to contain any valid UTF8 character, but the token may impose subset restrictions.
    def C_InitToken(pin, label)
      @pk.C_InitToken(@slot, pin, label.ljust(32, " "))
    end
    alias init_token C_InitToken
    
    # Opens a session between an application and a token in a particular slot.
    # flags indicates the type of session.
    def C_OpenSession(flags)
      nr = @pk.C_OpenSession(@slot, flags)
      sess = Session.new @pk, nr
      if block_given?
        begin
          yield sess
        ensure
          sess.close
        end
      else
        sess
      end
    end
    alias open C_OpenSession
  end
  
  # Closes all sessions an application has with a token.
  def C_CloseAllSessions
    @pk.C_CloseAllSessions(@slot)
  end
end
