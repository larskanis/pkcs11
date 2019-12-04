require 'pkcs11/helper'

module PKCS11
  # Cryptoki requires that an application open one or more sessions with a token to gain
  # access to the token's objects and functions. A session provides a logical connection
  # between the application and the token. A session can be a read/write (R/W) session or a
  # read-only (R/O) session (default).
  class Session
    include Helper

    # @private
    def initialize(pkcs11, session) # :nodoc:
      @pk, @sess = pkcs11, session
    end

    # The session handle.
    # @return [Integer]
    def to_int
      @sess
    end
    alias to_i to_int

    # @private
    def inspect # :nodoc:
      "#<#{self.class} #{@sess.inspect}>"
    end

    # Logs a user into a token.
    # @param [Integer, Symbol] user_type  is the user type CKU_*;
    # @param [String] pin  is the user's PIN.
    # @return [PKCS11::Session]
    #
    # When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the
    # application's sessions will enter either the "R/W SO Functions" state, the "R/W User
    # Functions" state, or the "R/O User Functions" state. If the user type is
    # CKU_CONTEXT_SPECIFIC , the behavior of C_Login depends on the context in which
    # it is called. Improper use of this user type will raise
    # CKR_OPERATION_NOT_INITIALIZED.
    def C_Login(user_type, pin)
      @pk.C_Login(@sess, string_to_handle('CKU_', user_type), pin)
      self
    end
    alias login C_Login

    # Logs a user out from a token.
    #
    # Depending on the current user type, if the call succeeds, each of the application's
    # sessions will enter either the "R/W Public Session" state or the "R/O Public Session"
    # state.
    # @return [PKCS11::Session]
    def C_Logout()
      @pk.C_Logout(@sess)
      self
    end
    alias logout C_Logout

    # Closes the session between an application and a token.
    # @return [PKCS11::Session]
    def C_CloseSession()
      @pk.C_CloseSession(@sess)
      self
    end
    alias close C_CloseSession

    # Obtains information about a session.
    # @return [CK_SESSION_INFO]
    def C_GetSessionInfo()
      @pk.C_GetSessionInfo(@sess)
    end
    alias info C_GetSessionInfo
    
    # Initializes a search for token and session objects that match a
    # template.
    #
    # See {Session#find_objects} for convenience.
    # @param [Hash] find_template  points to a search template that
    #                 specifies the attribute values to match
    # The matching criterion is an exact byte-for-byte match with all attributes in the
    # template. Use empty Hash to find all objects.
    # @return [PKCS11::Session]
    def C_FindObjectsInit(find_template={})
      @pk.C_FindObjectsInit(@sess, to_attributes(find_template))
      self
    end

    # Continues a search for token and session objects that match a template,
    # obtaining additional object handles.
    #
    # See {Session#find_objects} for convenience
    # @return [Array<PKCS11::Object>] Returns an array of Object instances.
    def C_FindObjects(max_count)
      objs = @pk.C_FindObjects(@sess, max_count)
      objs.map{|obj| Object.new @pk, @sess, obj }
    end

    # Terminates a search for token and session objects.
    #
    # See {Session#find_objects} for convenience
    # @return [PKCS11::Session]
    def C_FindObjectsFinal
      @pk.C_FindObjectsFinal(@sess)
      self
    end

    # Convenience method for the {Session#C_FindObjectsInit}, {Session#C_FindObjects}, {Session#C_FindObjectsFinal} cycle.
    #
    # * If called with block, it iterates over all found objects.
    # * If called without block, it returns with an array of all found Object instances.
    # @return [Array<PKCS11::Object>]
    #
    # @example prints subject of all certificates stored in the token:
    #   session.find_objects(CLASS:  PKCS11::CKO_CERTIFICATE) do |obj|
    #     p OpenSSL::X509::Name.new(obj[:SUBJECT])
    #   end
    def find_objects(template={})
      all_objs = [] unless block_given?
      C_FindObjectsInit(template)
      begin
        loop do
          objs = C_FindObjects(20)
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


    # Creates a new Object based on given template.
    #
    # If {Session#C_CreateObject} is used to create a key object, the key object will have its
    # CKA_LOCAL attribute set to false. If that key object is a secret or private key
    # then the new key will have the CKA_ALWAYS_SENSITIVE attribute set to
    # false, and the CKA_NEVER_EXTRACTABLE attribute set to false.
    #
    # Only session objects can be created during a read-only session. Only public objects can
    # be created unless the normal user is logged in.
    #
    # @param [Hash] template  Attributes of the object to create.
    # @return [PKCS11::Object] the newly created object
    # @example Creating a 112 bit DES key from plaintext
    #     secret_key = session.create_object(
    #       CLASS: PKCS11::CKO_SECRET_KEY, KEY_TYPE: PKCS11::CKK_DES2,
    #       ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true,
    #       VALUE: '0123456789abcdef', LABEL: 'test_secret_key')
    def C_CreateObject(template={})
      handle = @pk.C_CreateObject(@sess, to_attributes(template))
      Object.new @pk, @sess, handle
    end
    alias create_object C_CreateObject

    # Initializes the normal user's PIN. This standard
    # allows PIN values to contain any valid UTF8 character, but the token may impose subset
    # restrictions.
    #
    # @param [String] pin
    # @return [PKCS11::Session]
    def C_InitPIN(pin)
      @pk.C_InitPIN(@sess, pin)
      self
    end
    alias init_pin C_InitPIN

    # Modifies the PIN of the user that is currently logged in, or the CKU_USER
    # PIN if the session is not logged in.
    #
    # @param [String] old_pin
    # @param [String] new_pin
    # @return [PKCS11::Session]
    def C_SetPIN(old_pin, new_pin)
      @pk.C_SetPIN(@sess, old_pin, new_pin)
      self
    end
    alias set_pin C_SetPIN

    class Cipher
      # @private
      def initialize(update_block) # :nodoc:
        @update_block = update_block
      end
      # Process a data part with the encryption operation.
      # @param [String] data  data to be processed
      # @return [String] output data
      def update(data)
        @update_block.call(data)
      end
      alias << update
    end

    class DigestCipher < Cipher
      # @private
      def initialize(update_block, digest_key_block) # :nodoc:
        super(update_block)
        @digest_key_block = digest_key_block
      end
      alias digest_update update
      # Continues a multiple-part message-digesting operation by digesting the
      # value of a secret key.
      # @param [PKCS11::Object] key  key to be processed
      # @return [String] output data
      def digest_key(key)
        @digest_key_block.call(key)
      end
    end

    def common_crypt( init, update, final, single, mechanism, key, data=nil) # :nodoc:
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
    
    def common_verify( init, update, final, single, mechanism, key, signature, data=nil ) # :nodoc:
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

    # Initializes an encryption operation.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  the encryption mechanism
    # @param [PKCS11::Object] key  the object handle of the encryption key.
    # @return [PKCS11::Session]
    #
    # See {Session#encrypt} for convenience
    #
    # The CKA_ENCRYPT attribute of the encryption key, which indicates whether the key
    # supports encryption, must be true.
    #
    # After calling {Session#C_EncryptInit}, the application can either call {Session#C_Encrypt} to encrypt data
    # in a single part; or call {Session#C_EncryptUpdate} zero or more times, followed by
    # {Session#C_EncryptFinal}, to encrypt data in multiple parts. The encryption operation is active
    # until the application uses a call to {Session#C_Encrypt} or {Session#C_EncryptFinal} to actually obtain the
    # final piece of ciphertext. To process additional data (in single or multiple parts), the
    # application must call {Session#C_EncryptInit} again.
    def C_EncryptInit(mechanism, key)
      @pk.C_EncryptInit(@sess, to_mechanism(mechanism), key)
      self
    end
    # Encrypts single-part data.
    #
    # See {Session#encrypt} for convenience
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_Encrypt(data, out_size=nil)
      @pk.C_Encrypt(@sess, data, out_size)
    end
    # Continues a multiple-part encryption operation, processing another
    # data part.
    #
    # See {Session#encrypt} for convenience
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_EncryptUpdate(data, out_size=nil)
      @pk.C_EncryptUpdate(@sess, data, out_size)
    end
    # Finishes a multiple-part encryption operation.
    #
    # See {Session#encrypt} for convenience
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_EncryptFinal(out_size=nil)
      @pk.C_EncryptFinal(@sess, out_size)
    end

    # Convenience method for the {Session#C_EncryptInit}, {Session#C_EncryptUpdate}, {Session#C_EncryptFinal} call flow.
    #
    # If no block is given, the single part operation {Session#C_EncryptInit}, {Session#C_Encrypt} is called.
    # If a block is given, the multi part operation ({Session#C_EncryptInit}, {Session#C_EncryptUpdate}, {Session#C_EncryptFinal})
    # is used. The given block is called once with a cipher object. There can be any number of
    # {Cipher#update} calls within the block, each giving the encryption result of this part as String.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  used key
    # @param [String] data  data to encrypt
    # @yield [PKCS11::Session::Cipher]  Cipher object for processing data parts
    # @return [String]  the final part of the encryption operation.
    #
    # @example for using single part operation
    #   iv = "12345678"
    #   cryptogram = session.encrypt( {DES_CBC_PAD: iv}, key, "block 1block 2" )
    #
    # @example for using multi part operation
    #   iv = "12345678"
    #   cryptogram = ''
    #   cryptogram << session.encrypt( {DES_CBC_PAD: iv}, key ) do |cipher|
    #     cryptogram << cipher.update("block 1")
    #     cryptogram << cipher.update("block 2")
    #   end
    #
    # @example Calculating a key check value to a secret key
    #     key_kcv = session.encrypt( :DES3_ECB, key, "\0"*8)
    def encrypt(mechanism, key, data=nil, &block)
      common_crypt(:C_EncryptInit, :C_EncryptUpdate, :C_EncryptFinal, :C_Encrypt,
                   mechanism, key, data, &block)
    end

    # Initializes a decryption operation.
    #
    # See {Session#decrypt} for convenience and {Session#C_EncryptInit} for description.
    def C_DecryptInit(mechanism, key)
      @pk.C_DecryptInit(@sess, to_mechanism(mechanism), key)
    end
    # Decrypts encrypted data in a single part.
    #
    # See {Session#decrypt} for convenience.
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_Decrypt(data, out_size=nil)
      @pk.C_Decrypt(@sess, data, out_size)
    end
    # Continues a multiple-part decryption operation, processing another
    # encrypted data part.
    #
    # See {Session#decrypt} for convenience.
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_DecryptUpdate(data, out_size=nil)
      @pk.C_DecryptUpdate(@sess, data, out_size)
    end
    # Finishes a multiple-part decryption operation.
    #
    # See {Session#decrypt} for convenience.
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_DecryptFinal(out_size=nil)
      @pk.C_DecryptFinal(@sess, out_size)
    end

    # Convenience method for the {Session#C_DecryptInit}, {Session#C_DecryptUpdate}, {Session#C_DecryptFinal} call flow.
    #
    # @see Session#encrypt
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  used key
    # @param [String] data  data to decrypt
    # @yield [PKCS11::Session::Cipher]  Cipher object for processing data parts
    # @return [String]  the final part of the encryption operation.
    # @example Decrypt data previously encrypted with a RSA pulic key
    #     plaintext2 = session.decrypt( :RSA_PKCS, rsa_priv_key, cryptogram)
    def decrypt(mechanism, key, data=nil, &block)
      common_crypt(:C_DecryptInit, :C_DecryptUpdate, :C_DecryptFinal, :C_Decrypt,
                   mechanism, key, data, &block)
    end

    # Initializes a message-digesting operation.
    #
    # See {Session#digest} for convenience.
    # @return [PKCS11::Session]
    def C_DigestInit(mechanism)
      @pk.C_DigestInit(@sess, to_mechanism(mechanism))
      self
    end
    # Digests data in a single part.
    #
    # See {Session#digest} for convenience.
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_Digest(data, out_size=nil)
      @pk.C_Digest(@sess, data, out_size)
    end
    # Continues a multiple-part message-digesting operation, processing
    # another data part.
    #
    # See {Session#digest} for convenience.
    # @return [PKCS11::Session]
    def C_DigestUpdate(data)
      @pk.C_DigestUpdate(@sess, data)
      self
    end
    # Continues a multiple-part message-digesting operation by digesting the
    # value of a secret key.
    #
    # See {Session#digest} for convenience.
    #
    # The message-digesting operation must have been initialized with {Session#C_DigestInit}. Calls to
    # this function and {Session#C_DigestUpdate} may be interspersed any number of times in any
    # order.
    # @return [PKCS11::Session]
    def C_DigestKey(key)
      @pk.C_DigestKey(@sess, key)
      self
    end
    # Finishes a multiple-part message-digesting operation, returning the
    # message digest as String.
    #
    # See {Session#digest} for convenience.
    # @param [Integer, nil] out_size  The buffer size for output data provided to the
    #    library. If nil, size is determined automatically.
    # @return [String]
    def C_DigestFinal(out_size=nil)
      @pk.C_DigestFinal(@sess, out_size)
    end

    # Convenience method for the {Session#C_DigestInit}, {Session#C_DigestUpdate}, {Session#C_DigestKey},
    # {Session#C_DigestFinal} call flow.
    #
    # @example
    #   digest_string = session.digest( :SHA_1 ) do |cipher|
    #     cipher.update("key prefix")
    #     cipher.digest_key(some_key)
    #   end
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [String] data  data to digest
    # @yield [PKCS11::Session::DigestCipher]  Cipher object for processing data parts
    # @return [String]  final message digest
    # @see Session#encrypt
    def digest(mechanism, data=nil, &block)
      C_DigestInit(mechanism)
      if block_given?
        raise "data not nil, but block given" if data
        yield DigestCipher.new(proc{|data_|
          C_DigestUpdate(data_)
        }, proc{|key_|
          C_DigestKey(key_)
        })
        C_DigestFinal()
      else
        C_Digest(data)
      end
    end

    # Initializes a signature operation, where the signature is an appendix to the
    # data.
    #
    # See {Session#sign} for convenience.
    # @return [PKCS11::Session]
    def C_SignInit(mechanism, key)
      @pk.C_SignInit(@sess, to_mechanism(mechanism), key)
      self
    end
    # Signs data in a single part, where the signature is an appendix to the data.
    #
    # See {Session#sign} for convenience.
    # @return [String]  message signature
    def C_Sign(data, out_size=nil)
      @pk.C_Sign(@sess, data, out_size)
    end
    # Continues a multiple-part signature operation, processing another data
    # part.
    #
    # See {Session#sign} for convenience.
    # @return [PKCS11::Session]
    def C_SignUpdate(data)
      @pk.C_SignUpdate(@sess, data)
      self
    end
    # Finishes a multiple-part signature operation, returning the signature.
    #
    # See {Session#sign} for convenience.
    # @return [String]  message signature
    def C_SignFinal(out_size=nil)
      @pk.C_SignFinal(@sess, out_size)
    end

    # Convenience method for the {Session#C_SignInit}, {Session#C_SignUpdate}, {Session#C_SignFinal} call flow.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  used key
    # @param [String] data  data to sign
    # @yield [PKCS11::Session::Cipher]  Cipher object for processing data parts
    # @return [String]  signature
    # @see Session#encrypt
    # @example Sign a text by a RSA private key
    #     signature = session.sign( :SHA1_RSA_PKCS, rsa_priv_key, "important text")
    def sign(mechanism, key, data=nil, &block)
      common_crypt(:C_SignInit, :C_SignUpdate, :C_SignFinal, :C_Sign,
                   mechanism, key, data, &block)
    end


    # Initializes a verification operation, where the signature is an appendix to
    # the data.
    #
    # See {Session#verify} for convenience.
    def C_VerifyInit(mechanism, key)
      @pk.C_VerifyInit(@sess, to_mechanism(mechanism), key)
    end
    # Verifies a signature in a single-part operation, where the signature is an
    # appendix to the data.
    #
    # See {Session#verify} for convenience.
    def C_Verify(data, out_size=nil)
      @pk.C_Verify(@sess, data, out_size)
    end
    # Continues a multiple-part verification operation, processing another
    # data part.
    #
    # See {Session#verify} for convenience.
    def C_VerifyUpdate(data)
      @pk.C_VerifyUpdate(@sess, data)
    end
    # Finishes a multiple-part verification operation, checking the signature.
    #
    # See {Session#verify} for convenience.
    # @return [Boolean] <tt>true</tt> for valid signature.
    def C_VerifyFinal(out_size=nil)
      @pk.C_VerifyFinal(@sess, out_size)
    end

    # Convenience method for the {Session#C_VerifyInit}, {Session#C_VerifyUpdate}, {Session#C_VerifyFinal} call flow.
    #
    # @see Session#encrypt
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  used key
    # @param [String] signature  signature
    # @param [String] data  data to verify against signature
    # @yield [PKCS11::Session::Cipher]  Cipher object for processing data parts
    # @return [Boolean] <tt>true</tt> for valid signature.
    # @example
    #     raise("wrong signature") unless session.verify(:SHA1_RSA_PKCS, rsa_pub_key, signature, plaintext)
    def verify(mechanism, key, signature, data=nil, &block)
      common_verify(:C_VerifyInit, :C_VerifyUpdate, :C_VerifyFinal, :C_Verify,
                   mechanism, key, signature, data, &block)
    end

    # Initializes a signature operation, where the data can be recovered
    # from the signature
    #
    # See {Session#sign_recover} for convenience.
    def C_SignRecoverInit(mechanism, key)
      @pk.C_SignRecoverInit(@sess, to_mechanism(mechanism), key)
      self
    end
    # Signs data in a single operation, where the data can be recovered from
    # the signature.
    #
    # See {Session#sign_recover} for convenience.
    def C_SignRecover(data, out_size=nil)
      @pk.C_SignRecover(@sess, data, out_size)
    end

    # Convenience method for the {Session#C_SignRecoverInit}, {Session#C_SignRecover} call flow.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  signature key
    # @param [String] data  data to be recovered
    # @return [String]  signature
    # @see Session#verify_recover
    def sign_recover(mechanism, key, data)
      C_SignRecoverInit(mechanism, key)
      C_SignRecover(data)
    end

    
    # Initializes a signature verification operation, where the data can be recovered
    # from the signature
    #
    # See {Session#verify_recover} for convenience.
    def C_VerifyRecoverInit(mechanism, key)
      @pk.C_VerifyRecoverInit(@sess, to_mechanism(mechanism), key)
    end
    # Verifies a signature in a single-part operation, where the data is
    # recovered from the signature.
    #
    # See {Session#verify_recover} for convenience.
    def C_VerifyRecover(signature, out_size=nil)
      @pk.C_VerifyRecover(@sess, signature, out_size=nil)
    end

    # Convenience method for the {Session#C_VerifyRecoverInit}, {Session#C_VerifyRecover} call flow.
    # 
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] key  verification key
    # @return [String] recovered data
    # @see Session#sign_recover
    def verify_recover(mechanism, key, signature)
      C_VerifyRecoverInit(mechanism, key)
      C_VerifyRecover(signature)
    end
    
    # Continues multiple-part digest and encryption operations,
    # processing another data part.
    #
    # Digest and encryption operations must both be active (they must have been initialized
    # with {Session#C_DigestInit} and {Session#C_EncryptInit}, respectively). This function may be called any
    # number of times in succession, and may be interspersed with {Session#C_DigestUpdate},
    # {Session#C_DigestKey}, and {Session#C_EncryptUpdate} calls.
    def C_DigestEncryptUpdate(data, out_size=nil)
      @pk.C_DigestEncryptUpdate(@sess, data, out_size)
    end

    # Continues a multiple-part combined decryption and digest
    # operation, processing another data part.
    #
    # Decryption and digesting operations must both be active (they must have been initialized
    # with {Session#C_DecryptInit} and {Session#C_DigestInit}, respectively). This function may be called any
    # number of times in succession, and may be interspersed with {Session#C_DecryptUpdate},
    # {Session#C_DigestUpdate}, and {Session#C_DigestKey} calls.
    def C_DecryptDigestUpdate(data, out_size=nil)
      @pk.C_DecryptDigestUpdate(@sess, data, out_size)
    end

    # Continues a multiple-part combined signature and encryption
    # operation, processing another data part.
    #
    # Signature and encryption operations must both be active (they must have been initialized
    # with {Session#C_SignInit} and {Session#C_EncryptInit}, respectively). This function may be called any
    # number of times in succession, and may be interspersed with {Session#C_SignUpdate} and
    # {Session#C_EncryptUpdate} calls.
    def C_SignEncryptUpdate(data, out_size=nil)
      @pk.C_SignEncryptUpdate(@sess, data, out_size)
    end
    
    # Continues a multiple-part combined decryption and
    # verification operation, processing another data part.
    #
    # Decryption and signature operations must both be active (they must have been initialized
    # with {Session#C_DecryptInit} and {Session#C_VerifyInit}, respectively). This function may be called any
    # number of times in succession, and may be interspersed with {Session#C_DecryptUpdate} and
    # {Session#C_VerifyUpdate} calls.
    def C_DecryptVerifyUpdate(data, out_size=nil)
      @pk.C_DecryptVerifyUpdate(@sess, data, out_size)
    end

    # Generates a secret key Object or set of domain parameters, creating a new
    # Object.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [Hash] template  Attributes of the key to create.
    # @return [PKCS11::Object]  key Object of the new created key.
    # @example generate 112 bit DES key
    #     key = session.generate_key(:DES2_KEY_GEN,
    #       {ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true})
    def C_GenerateKey(mechanism, template={})
      obj = @pk.C_GenerateKey(@sess, to_mechanism(mechanism), to_attributes(template))
      Object.new @pk, @sess, obj
    end
    alias generate_key C_GenerateKey

    # Generates a public/private key pair, creating new key Object instances.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [Hash] pubkey_template  Attributes of the public key to create.
    # @param [Hash] privkey_template  Attributes of the private key to create.
    # @return [Array<PKCS11::Object>]  an two-items array of new created public and private key Object.
    # @example
    #     pub_key, priv_key = session.generate_key_pair(:RSA_PKCS_KEY_PAIR_GEN,
    #       {ENCRYPT: true, VERIFY: true, WRAP: true, MODULUS_BITS: 768, PUBLIC_EXPONENT: 3},
    #       {SUBJECT: 'test', ID: "ID", DECRYPT: true, SIGN: true, UNWRAP: true})
    def C_GenerateKeyPair(mechanism, pubkey_template={}, privkey_template={})
      objs = @pk.C_GenerateKeyPair(@sess, to_mechanism(mechanism), to_attributes(pubkey_template), to_attributes(privkey_template))
      objs.map{|obj| Object.new @pk, @sess, obj }
    end
    alias generate_key_pair C_GenerateKeyPair

    # Wraps (i.e., encrypts) a private or secret key.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] wrapping_key  wrapping key
    # @param [PKCS11::Object] wrapped_key  key to wrap
    # @return [String]  the encrypted binary data.
    # @see Session#C_UnwrapKey
    # @example Wrapping a secret key
    #     wrapped_key_value = session.wrap_key(:DES3_ECB, secret_key, secret_key)
    # @example Wrapping a private key
    #     wrapped_key_value = session.wrap_key({DES3_CBC_PAD: "\0"*8}, secret_key, rsa_priv_key)
    def C_WrapKey(mechanism, wrapping_key, wrapped_key, out_size=nil)
      @pk.C_WrapKey(@sess, to_mechanism(mechanism), wrapping_key, wrapped_key, out_size)
    end
    alias wrap_key C_WrapKey

    # Unwraps (i.e. decrypts) a wrapped key, creating a new private key or
    # secret key object.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] wrapping_key  wrapping key
    # @param [String] wrapped_key  key data of the wrapped key
    # @return [PKCS11::Object]  key object of the new created key.
    # @see Session#C_WrapKey
    # @example
    #     unwrapped_key = session.unwrap_key(:DES3_ECB, secret_key, wrapped_key_value,
    #         CLASS: CKO_SECRET_KEY, KEY_TYPE: CKK_DES2, ENCRYPT: true, DECRYPT: true)
    def C_UnwrapKey(mechanism, wrapping_key, wrapped_key, template={})
      obj = @pk.C_UnwrapKey(@sess, to_mechanism(mechanism), wrapping_key, wrapped_key, to_attributes(template))
      Object.new @pk, @sess, obj
    end
    alias unwrap_key C_UnwrapKey

    # Derives a key from a base key, creating a new key object.
    #
    # @param [Hash, Symbol, Integer, PKCS11::CK_MECHANISM] mechanism  used mechanism
    # @param [PKCS11::Object] base_key  key to derive
    # @param [Hash] template  Attributes of the object to create.
    # @return [PKCS11::Object]  key object of the new created key.
    # @example Derive a AES key by XORing with some derivation data
    #     deriv_data = "\0"*16
    #     new_key = session.derive_key( {CKM_XOR_BASE_AND_DATA => {pData:  deriv_data}}, secret_key,
    #       CLASS: CKO_SECRET_KEY, KEY_TYPE: CKK_AES, VALUE_LEN: 16, ENCRYPT: true )
    def C_DeriveKey(mechanism, base_key, template={})
      obj = @pk.C_DeriveKey(@sess, to_mechanism(mechanism), base_key, to_attributes(template))
      Object.new @pk, @sess, obj
    end
    alias derive_key C_DeriveKey

    # Mixes additional seed material into the token's random number
    # generator.
    # @param [String] entropy data
    # @return [PKCS11::Session]
    def C_SeedRandom(data)
      @pk.C_SeedRandom(@sess, data)
      self
    end
    alias seed_random C_SeedRandom
    
    # Generates random or pseudo-random data.
    #
    # @param [Integer] out_size
    # @return [String]  random or pseudo-random binary data of <tt>out_size</tt> bytes.
    def C_GenerateRandom(out_size)
      @pk.C_GenerateRandom(@sess, out_size)
    end
    alias generate_random C_GenerateRandom
    
    # Obtains a copy of the cryptographic operations state of a session,
    # encoded as a string of bytes.
    # @return [String]
    # @see Session#C_SetOperationState
    def C_GetOperationState
      @pk.C_GetOperationState(@sess)
    end
    alias get_operation_state C_GetOperationState

    # Restores the cryptographic operations state of a session from a
    # string of bytes obtained with {Session#C_GetOperationState}.
    #
    # @param [String] state  previously stored session state
    # @param [PKCS11::Object]  encryption key for sessions stored without keys
    # @param [PKCS11::Object]  authentication key for sessions stored without keys
    # @return [PKCS11::Session]
    def C_SetOperationState(state, enc_key=nil, auth_key=nil)
      @pk.C_SetOperationState(@sess, state, enc_key||0, auth_key||0)
      self
    end
    alias set_operation_state C_SetOperationState
  end
end
