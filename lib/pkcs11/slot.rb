require 'pkcs11/helper'

module PKCS11
  # Each slot corresponds to a physical reader or other device interface.
  # It may contain a token.
  class Slot
    include Helper

    def initialize(pkcs11, slot) # :nodoc:
      @pk, @slot = pkcs11, slot
    end

    # The slot handle.
    def to_int
      @slot
    end
    alias to_i to_int

    def inspect # :nodoc:
      "#<#{self.class} #{@slot.inspect}>"
    end

    # Obtains information about a particular slot in the system.
    def C_GetSlotInfo
      @pk.C_GetSlotInfo(@slot)
    end
    alias info C_GetSlotInfo
    
    # Obtains information about a particular token in the system.
    def C_GetTokenInfo
      @pk.C_GetTokenInfo(@slot)
    end
    alias token_info C_GetTokenInfo
    
    # Waits for a slot event, such as token insertion or token removal, to
    # occur. flags determines whether or not the C_WaitForSlotEvent call blocks (i.e., waits
    # for a slot event to occur);
    def C_WaitForSlotEvent(flags)
      @pk.C_WaitForSlotEvent(@slot, flags)
    end
    alias wait_for_event C_WaitForSlotEvent

    # C_GetMechanismList is used to obtain a list of mechanism types supported by a token.
    def C_GetMechanismList
      @pk.C_GetMechanismList(@slot).map{|mech|
        Mechanism.new MECHANISMS, mech
      }
    end
    alias mechanisms C_GetMechanismList

    # Obtains information about a particular mechanism possibly
    # supported by a token.
    def C_GetMechanismInfo(mechanism)
      @pk.C_GetMechanismInfo(@slot, to_mechanism(mechanism))
    end
    alias mechanism_info C_GetMechanismInfo

    # Initializes a token. pin is the SO’s initial PIN; label is the label of the token (max 32-byte). This standard allows PIN
    # values to contain any valid UTF8 character, but the token may impose subset restrictions.
    def C_InitToken(pin, label)
      @pk.C_InitToken(@slot, pin, label.ljust(32, " "))
    end
    alias init_token C_InitToken
    
    # Opens a Session between an application and a token in a particular slot.
    #
    # flags:: indicates the type of session. Default is read-only,
    #         use <tt>CKF_SERIAL_SESSION | CKF_RW_SESSION</tt> for read-write session.
    #
    # * If called with block, yields the block with the session and closes the session
    # when the is finished.
    # * If called without block, returns the session object.
    def C_OpenSession(flags=CKF_SERIAL_SESSION)
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
    
    # Closes all sessions an application has with a token.
    def C_CloseAllSessions
      @pk.C_CloseAllSessions(@slot)
    end
    alias close_all_sessions C_CloseAllSessions
  end
end
