require 'pkcs11/helper'

module PKCS11
  # Each slot corresponds to a physical reader or other device interface.
  # It may contain a token.
  class Slot
    include Helper

    # @private
    def initialize(pkcs11, slot) # :nodoc:
      @pk, @slot = pkcs11, slot
    end

    # The slot handle.
    # @return [Integer]
    def to_int
      @slot
    end
    alias to_i to_int

    # @private
    def inspect # :nodoc:
      "#<#{self.class} #{@slot.inspect}>"
    end

    # Obtains information about a particular slot in the system.
    # @return [PKCS11::CK_SLOT_INFO]
    def C_GetSlotInfo
      @pk.C_GetSlotInfo(@slot)
    end
    alias info C_GetSlotInfo

    # Obtains information about a particular token in the system.
    # @return [PKCS11::CK_TOKEN_INFO]
    def C_GetTokenInfo
      @pk.C_GetTokenInfo(@slot)
    end
    alias token_info C_GetTokenInfo

    # C_GetMechanismList is used to obtain a list of mechanism types supported by a token.
    # @return [Array<PKCS11::CKM_*>]
    def C_GetMechanismList
      @pk.C_GetMechanismList(@slot)
    end
    alias mechanisms C_GetMechanismList

    # Obtains information about a particular mechanism possibly
    # supported by a token.
    #
    # @param [Integer, Symbol] mechanism
    # @return [CK_MECHANISM_INFO]
    def C_GetMechanismInfo(mechanism)
      @pk.C_GetMechanismInfo(@slot, string_to_handle('CKM_', mechanism))
    end
    alias mechanism_info C_GetMechanismInfo

    # Initializes a token.
    # @param [String] pin is the SO's initial PIN
    # @param [String] label is the label of the token (max 32-byte).
    #
    # The standard allows PIN
    # values to contain any valid UTF8 character, but the token may impose subset restrictions.
    # @return [PKCS11::Slot]
    def C_InitToken(pin, label)
      @pk.C_InitToken(@slot, pin, label.ljust(32, " "))
      self
    end
    alias init_token C_InitToken

    # Opens a Session between an application and a token in a particular slot.
    #
    # @param [Integer] flags  indicates the type of session. Default is read-only,
    #         use <tt>CKF_SERIAL_SESSION | CKF_RW_SESSION</tt> for read-write session.
    #
    # * If called with block, yields the block with the session and closes the session
    #   when the is finished.
    # * If called without block, returns the session object.
    # @return [PKCS11::Session]
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
    # @return [PKCS11::Slot]
    def C_CloseAllSessions
      @pk.C_CloseAllSessions(@slot)
      self
    end
    alias close_all_sessions C_CloseAllSessions
  end
end
