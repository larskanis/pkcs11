class PKCS11
  class Session
    def self.hash_to_attributes(template)
      case template
        when Array
          template.map{|v| PKCS11::CK_ATTRIBUTE.new(string_to_handle('CKA_', v), nil) }
        when Hash
          template.map{|k,v| PKCS11::CK_ATTRIBUTE.new(string_to_handle('CKA_', k), v) }
        else
          template
      end
    end
    
    def self.string_to_handle(prefix, attribute)
      case attribute
        when String, Symbol
          PKCS11.const_get("#{prefix}#{attribute}")
        else
          attribute
      end
    end
    
    def self.hash_to_mechanism(hash)
      case hash
        when String, Symbol
          PKCS11::CK_MECHANISM.new(string_to_handle('CKM_', hash))
        when Hash
          raise "only one mechanism allowed" unless hash.length==1
          PKCS11::CK_MECHANISM.new(string_to_handle('CKM_', hash.keys.first), hash.values.first)
        else
          hash
      end
    end

    def initialize(pkcs11, session)
      @pk, @sess = pkcs11, session
    end

    def to_int
      @sess
    end
    alias to_i to_int

    def inspect
      "#<#{self.class} #{@sess.inspect}>"
    end

    # Logs a user into a token. user_type is the user type;
    # pin is the user’s PIN.
    #
    # When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the
    # application's sessions will enter either the "R/W SO Functions" state, the "R/W User
    # Functions" state, or the "R/O User Functions" state. If the user type is
    # CKU_CONTEXT_SPECIFIC , the behavior of C_Login depends on the context in which
    # it is called. Improper use of this user type will result in a return value
    # CKR_OPERATION_NOT_INITIALIZED.
    def C_Login(user_type, pin)
      @pk.C_Login(@sess, user_type, pin)
    end
    alias login C_Login

    # Logs a user out from a token.
    #
    # Depending on the current user type, if the call succeeds, each of the application’s
    # sessions will enter either the “R/W Public Session” state or the “R/O Public Session”
    # state.
    def C_Logout()
      @pk.C_Logout(@sess)
    end
    alias logout C_Logout

    # Closes the session between an application and a token.
    def C_CloseSession()
      @pk.C_CloseSession(@sess)
    end
    alias close C_CloseSession

    def C_FindObjectsInit(find_template)
      @pk.C_FindObjectsInit(@sess, find_template)
    end
    def C_FindObjects(max_count)
      objs = @pk.C_FindObjects(@sess, max_count)
      objs.map{|obj| Object.new @pk, @sess, obj }
    end
    def C_FindObjectsFinal
      @pk.C_FindObjectsFinal(@sess)
    end

    def find_objects(template={})
      template = Session.hash_to_attributes template

      all_objs = [] unless block_given?
      C_FindObjectsInit(template)
      begin
        loop do
          objs = C_FindObjects(4)
          break if objs.empty?
          if block_given?
            objs.each{|obj| yield obj }
          else
            all_objs += objs
          end
        end
      ensure
        C_FindObjectsFinal()
      end
      return all_objs
    end


    # Creates a new object based on given template. Returns a new object’s handle.
    # If C_CreateObject is used to create a key object, the key object will have its
    # CKA_LOCAL attribute set to false. If that key object is a secret or private key
    # then the new key will have the CKA_ALWAYS_SENSITIVE attribute set to
    # false, and the CKA_NEVER_EXTRACTABLE attribute set to false.
    # Only session objects can be created during a read-only session. Only public objects can
    # be created unless the normal user is logged in.
    def C_CreateObject(template={})
      handle = @pk.C_CreateObject(@sess, Session.hash_to_attributes(template))
      Object.new @pk, @sess, handle
    end
    alias create_object C_CreateObject

    # Initializes the normal user’s PIN. This standard
    # allows PIN values to contain any valid UTF8 character, but the token may impose subset
    # restrictions.
    def C_InitPIN(pin)
      @pk.C_InitPIN(@sess, pin)
    end
    alias init_pin C_InitPIN

    # Modifies the PIN of the user that is currently logged in, or the CKU_USER
    # PIN if the session is not logged in.
    def C_SetPIN(old_pin, new_pin)
      @pk.C_SetPIN(@sess, old_pin, new_pin)
    end
    alias set_pin C_SetPIN

    class Cipher
      def initialize(update_block)
        @update_block = update_block
      end
      def update(data)
        @update_block.call(data)
      end
      alias << update
    end

    def common_crypt( init, update, final, single, mechanism, key, data=nil)
      send(init, mechanism, key)
      if block_given?
        raise "data not nil, but block given" if data
        yield Cipher.new(proc{|data_|
          send(update, data_)
        })
        send(final)
      else
        send(single, data)
      end
    end
    private :common_crypt
    
    def common_verify( init, update, final, single, mechanism, key, signature, data=nil )
      send(init, mechanism, key)
      if block_given?
        raise "data not nil, but block given" if data
        yield Cipher.new(proc{|data_|
          send(update, data_)
        })
        send(final, signature)
      else
        send(single, data, signature)
      end
    end
    private :common_verify

    def common_digest( init, update, final, single, mechanism, data=nil )
      send(init, mechanism)
      if block_given?
        raise "data not nil, but block given" if data
        yield Cipher.new(proc{|data_|
          send(update, data_)
        })
        send(final)
      else
        send(single, data)
      end
    end
    private :common_digest

    # Initializes an encryption operation.
    #
    # * <tt>mechanism</tt> : the encryption mechanism, Hash, String or Integer
    # * <tt>key</tt> : the object handle of the encryption key.
    #
    # The CKA_ENCRYPT attribute of the encryption key, which indicates whether the key
    # supports encryption, must be true.
    #
    # After calling C_EncryptInit, the application can either call C_Encrypt to encrypt data
    # in a single part; or call C_EncryptUpdate zero or more times, followed by
    # C_EncryptFinal, to encrypt data in multiple parts. The encryption operation is active
    # until the application uses a call to C_Encrypt or C_EncryptFinal to actually obtain the
    # final piece of ciphertext. To process additional data (in single or multiple parts), the
    # application must call C_EncryptInit again.
    def C_EncryptInit(mechanism, key)
      @pk.C_EncryptInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_Encrypt(data, out_size=nil)
      @pk.C_Encrypt(@sess, data, out_size)
    end
    def C_EncryptUpdate(data, out_size=nil)
      @pk.C_EncryptUpdate(@sess, data, out_size)
    end
    def C_EncryptFinal(out_size=nil)
      @pk.C_EncryptFinal(@sess, out_size)
    end

    # Convenience method for the C_EncryptInit, C_EncryptUpdate, C_EncryptFinal call flow.
    #
    # Exsample:
    #   iv = "12345678"
    #   cryptogram = ''
    #   cryptogram << session.encrypt( {:DES_CBC_PAD=>iv}, key ) do |cipher|
    #     cryptogram << cipher.update("block 1")
    #     cryptogram << cipher.update("block 2")
    #   end
    def encrypt(mechanism, key, data=nil, &block)
      common_crypt(:C_EncryptInit, :C_EncryptUpdate, :C_EncryptFinal, :C_Encrypt,
                   mechanism, key, data, &block)
    end

    # The same like C_EncryptInit() but for decryption.
    def C_DecryptInit(mechanism, key)
      @pk.C_DecryptInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_Decrypt(data, out_size=nil)
      @pk.C_Decrypt(@sess, data, out_size)
    end
    def C_DecryptUpdate(data, out_size=nil)
      @pk.C_DecryptUpdate(@sess, data, out_size)
    end
    def C_DecryptFinal(out_size=nil)
      @pk.C_DecryptFinal(@sess, out_size)
    end

    # Convenience method for the C_DecryptInit, C_DecryptUpdate, C_DecryptFinal call flow.
    #
    # See encrypt()
    def decrypt(mechanism, key, data=nil, &block)
      common_crypt(:C_DecryptInit, :C_DecryptUpdate, :C_DecryptFinal, :C_Decrypt,
                   mechanism, key, data, &block)
    end

    # The same like C_EncryptInit() but for message-digesting.
    def C_DigestInit(mechanism)
      @pk.C_DigestInit(@sess, Session.hash_to_mechanism(mechanism))
    end
    def C_Digest(data, out_size=nil)
      @pk.C_Digest(@sess, data, out_size)
    end
    def C_DigestUpdate(data)
      @pk.C_DigestUpdate(@sess, data)
    end
    def C_DigestFinal(out_size=nil)
      @pk.C_DigestFinal(@sess, out_size)
    end

    # Convenience method for the C_DigestInit, C_DigestUpdate, C_DigestFinal call flow.
    #
    # See encrypt()
    def digest(mechanism, data=nil, &block)
      common_digest(:C_DigestInit, :C_DigestUpdate, :C_DigestFinal, :C_Digest,
                   mechanism, data, &block)
    end

    # The same like C_EncryptInit() but for signing.
    def C_SignInit(mechanism, key)
      @pk.C_SignInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_Sign(data, out_size=nil)
      @pk.C_Sign(@sess, data, out_size)
    end
    def C_SignUpdate(data)
      @pk.C_SignUpdate(@sess, data)
    end
    def C_SignFinal(out_size=nil)
      @pk.C_SignFinal(@sess, out_size)
    end

    # Convenience method for the C_SignInit, C_SignUpdate, C_SignFinal call flow.
    #
    # See encrypt()
    def sign(mechanism, key, data=nil, &block)
      common_crypt(:C_SignInit, :C_SignUpdate, :C_SignFinal, :C_Sign,
                   mechanism, key, data, &block)
    end


    # The same like C_EncryptInit() but for verification.
    def C_VerifyInit(mechanism, key)
      @pk.C_VerifyInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_Verify(data, out_size=nil)
      @pk.C_Verify(@sess, data, out_size)
    end
    def C_VerifyUpdate(data)
      @pk.C_VerifyUpdate(@sess, data)
    end
    def C_VerifyFinal(out_size=nil)
      @pk.C_VerifyFinal(@sess, out_size)
    end

    # Convenience method for the C_VerifyInit, C_VerifyUpdate, C_VerifyFinal call flow.
    #
    # See encrypt()
    def verify(mechanism, key, signature, data=nil, &block)
      common_verify(:C_VerifyInit, :C_VerifyUpdate, :C_VerifyFinal, :C_Verify,
                   mechanism, key, signature, data, &block)
    end

    # Initializes a signature operation, where the data can be recovered
    # from the signature
    def C_SignRecoverInit(mechanism, key)
      @pk.C_SignRecoverInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_SignRecover(data, out_size=nil)
      @pk.C_SignRecover(@sess, data, out_size)
    end

    # Convenience method for the C_SignRecoverInit, C_SignRecover call flow.
    def sign_recover(mechanism, key, data)
      C_SignRecoverInit(mechanism, key)
      C_SignRecover(data)
    end

    
    # Initializes a signature verification operation, where the data can be recovered
    # from the signature
    def C_VerifyRecoverInit(mechanism, key)
      @pk.C_VerifyRecoverInit(@sess, Session.hash_to_mechanism(mechanism), key)
    end
    def C_VerifyRecover(signature, out_size=nil)
      @pk.C_VerifyRecover(@sess, signature, out_size=nil)
    end

    # Convenience method for the C_VerifyRecoverInit, C_VerifyRecover call flow.
    def verify_recover(mechanism, key, signature)
      C_VerifyRecoverInit(mechanism, key)
      C_VerifyRecover(signature)
    end
    
    # Continues multiple-part digest and encryption operations,
    # processing another data part.
    #
    # Digest and encryption operations must both be active (they must have been initialized
    # with C_DigestInit and C_EncryptInit, respectively). This function may be called any
    # number of times in succession, and may be interspersed with C_DigestUpdate,
    # C_DigestKey, and C_EncryptUpdate calls.
    def C_DigestEncryptUpdate(data, out_size=nil)
      @pk.C_DigestEncryptUpdate(@sess, data, out_size)
    end

    # Continues a multiple-part combined decryption and digest
    # operation, processing another data part.
    #
    # Decryption and digesting operations must both be active (they must have been initialized
    # with C_DecryptInit and C_DigestInit, respectively). This function may be called any
    # number of times in succession, and may be interspersed with C_DecryptUpdate,
    # C_DigestUpdate, and C_DigestKey calls.
    def C_DecryptDigestUpdate(data, out_size=nil)
      @pk.C_DecryptDigestUpdate(@sess, data, out_size)
    end

    # Continues a multiple-part combined signature and encryption
    # operation, processing another data part.
    #
    # Signature and encryption operations must both be active (they must have been initialized
    # with C_SignInit and C_EncryptInit, respectively). This function may be called any
    # number of times in succession, and may be interspersed with C_SignUpdate and
    # C_EncryptUpdate calls.
    def C_SignEncryptUpdate(data, out_size=nil)
      @pk.C_SignEncryptUpdate(@sess, data, out_size)
    end
    
    # Continues a multiple-part combined decryption and
    # verification operation, processing another data part.
    #
    # Decryption and signature operations must both be active (they must have been initialized
    # with C_DecryptInit and C_VerifyInit, respectively). This function may be called any
    # number of times in succession, and may be interspersed with C_DecryptUpdate and
    # C_VerifyUpdate calls.
    def C_DecryptVerifyUpdate(data, out_size=nil)
      @pk.C_DecryptVerifyUpdate(@sess, data, out_size)
    end

    # Generates a secret key or set of domain parameters, creating a new
    # object.
    #
    # Returns key object of the new created key.
    def C_GenerateKey(mechanism, template={})
      obj = @pk.C_GenerateKey(@sess, Session.hash_to_mechanism(mechanism), Session.hash_to_attributes(template))
      Object.new @pk, @sess, obj
    end

    # Generates a public/private key pair, creating new key objects.
    #
    # Returns key object of the new created key.
    def C_GenerateKeyPair(mechanism, pubkey_template={}, privkey_template={})
      obj = @pk.C_GenerateKeyPair(@sess, Session.hash_to_mechanism(mechanism), pubkey_template, privkey_template)
      Object.new @pk, @sess, obj
    end

    # Wraps (i.e., encrypts) a private or secret key.
    #
    # Returns the encrypted binary data.
    def C_WrapKey(mechanism, wrapping_key, wrapped_key, out_size=nil)
      @pk.C_WrapKey(@sess, Session.hash_to_mechanism(mechanism), wrapping_key, wrapped_key, out_size)
    end

    # Unwraps (i.e. decrypts) a wrapped key, creating a new private key or
    # secret key object.
    #
    # Returns key object of the new created key.
    def C_UnwrapKey(mechanism, wrapping_key, wrapped_key, template={})
      obj = @pk.C_UnwrapKey(@sess, Session.hash_to_mechanism(mechanism), wrapping_key, wrapped_key, Session.hash_to_attributes(template))
      Object.new @pk, @sess, obj
    end

    # Derives a key from a base key, creating a new key object.
    #
    # Returns key object of the new created key.
    def C_DeriveKey(mechanism, base_key, template={})
      obj = @pk.C_DeriveKey(@sess, Session.hash_to_mechanism(mechanism), base_key, Session.hash_to_attributes(template))
      Object.new @pk, @sess, obj
    end

    # Mixes additional seed material into the token’s random number
    # generator.
    def C_SeedRandom(data)
      @pk.C_SeedRandom(@sess, data)
    end
    
    # Generates random or pseudo-random data.
    #
    # Returns random or pseudo-random binary data of <tt>out_size</tt> bytes.
    def C_GenerateRandom(out_size)
      @pk.C_GenerateRandom(@sess, out_size)
    end
  end
end
