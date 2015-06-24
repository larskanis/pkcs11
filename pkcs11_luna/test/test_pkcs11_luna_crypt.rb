require "minitest/autorun"
require "pkcs11_luna"
require "test/luna_helper"

class TestPkcs11LunaCrypt < Minitest::Test
  include PKCS11
  
  def setup
    @pk = Luna::Library.new
    slot_id, password = LunaHelper.get_slot_password()
    @slot = Slot.new(@pk, slot_id)    
    @session = @slot.open(PKCS11::CKF_RW_SESSION | PKCS11::CKF_SERIAL_SESSION)
    @session.login(:USER, password)
  end
  
  def teardown
    @session.logout
    @session.close
    @pk.close
  end
  
  def destroy_object(session, label)
    session.find_objects(:LABEL=>label) do |obj|
      obj.destroy
    end
  end

  
  def test_ec_pair_gen_derive_aes
    pub_label = "EC Public Key"
    priv_label = "EC Private Key"
    derived_label = "EC Derived Key "
    destroy_object(@session, pub_label)
    destroy_object(@session, priv_label)
    destroy_object(@session, derived_label + '1')
    destroy_object(@session, derived_label + '2')
        
    #DER encoding of OID 1.3.132.0.10 secp256k1
    curve_oid_der = [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A].pack("C*")
        
    attributes_public = {:TOKEN=>true, :ENCRYPT=>true, :VERIFY=>true, :WRAP=>true,
      :EC_PARAMS=>curve_oid_der, :LABEL=>pub_label}
    attributes_private = {:TOKEN=>true, :DECRYPT=>true, :SIGN=>true, 
      :DERIVE=>true, :UNWRAP=>true, :SENSITIVE=>true, :LABEL=>priv_label}
                             
    pub_key1, priv_key1 = @session.generate_key_pair(:EC_KEY_PAIR_GEN, attributes_public, attributes_private)    
    pub_key2, priv_key2 = @session.generate_key_pair(:EC_KEY_PAIR_GEN, attributes_public, attributes_private)
    
    shared_data = "SHARED DATA"
    
    ec_point1 = pub_key1.attributes(:EC_POINT)[0].value
    ec_point2 = pub_key2.attributes(:EC_POINT)[0].value
    mechanism = {:ECDH1_DERIVE=>{:kdf=>Luna::CKD_SHA512_KDF, :pSharedData=>shared_data}}
      
    derive_attributes = {:CLASS=>CKO_SECRET_KEY, :KEY_TYPE=>CKK_AES, :TOKEN=>true, :SENSITIVE=>true, :PRIVATE=>true,
    :ENCRYPT=>true, :DECRYPT=>true, :SIGN=>true, :VERIFY=>true, :VALUE_LEN=>32, :LABEL=>derived_label+'1'}
    
    assert_raises(Luna::CKR_ECC_POINT_INVALID) do
      @session.derive_key(mechanism, priv_key1, derive_attributes)
    end
    
    mechanism[:ECDH1_DERIVE][:pPublicData] = ec_point2     
    derived_key1 = @session.derive_key(mechanism, priv_key1, derive_attributes)
    mechanism[:ECDH1_DERIVE][:pPublicData] = ec_point1
    derive_attributes[:LABEL] = derived_label + '2'
    derived_key2 = @session.derive_key(mechanism, priv_key2, derive_attributes)
    
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
    message = "Text to encrypt"
    cipher_text = @session.encrypt({:AES_CBC_PAD=>iv}, derived_key1, message)
    decrypted = @session.decrypt({:AES_CBC_PAD=>iv}, derived_key2, cipher_text)
    assert_equal(decrypted, message)    
  end
  
  def test_encrypt_decrypt_aes
    label = "Test AES Key"
    destroy_object(@session, label)
    key = @session.generate_key(:AES_KEY_GEN,
      :CLASS=>CKO_SECRET_KEY, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
      :TOKEN=>true, :VALUE_LEN=>32, :LABEL=>label)
      
    assert key[Luna::CKA_FINGERPRINT_SHA256].size == 32
      
    message = "Text to encrypt"
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
    cipher_text = @session.encrypt({:AES_CBC_PAD=>iv}, key, message)
    decrypted_text = @session.decrypt({:AES_CBC_PAD=>iv}, key, cipher_text)
    assert_equal(message, decrypted_text)
  end
  
  def test_generate_rsa_key_pair
    pub_label = "Test RSA public key"
    priv_label = "Test RSA private key"
    destroy_object(@session, pub_label)
    destroy_object(@session, priv_label)
    
    pub_attr = {:ENCRYPT=>true, :VERIFY=>true, 
      :MODULUS_BITS=>2048, :TOKEN=>true, :WRAP=>true, :LABEL=>pub_label}
    priv_attr = {:DECRYPT=>true, :SIGN=>true, :SENSITIVE=>true, :PRIVATE=>true, 
          :TOKEN=>true, :UNWRAP=>true, :LABEL=>priv_label}
    
    pub_key, priv_key = @session.generate_key_pair(:RSA_FIPS_186_3_AUX_PRIME_KEY_PAIR_GEN, pub_attr, priv_attr)    
  end
  
  def test_encrypt_decrypt_rsa
    pub_key, priv_key = test_generate_rsa_key_pair
    message = "Text to encrypt using RSA keys"
    encrypted = @session.encrypt(:RSA_PKCS, pub_key, message)
    decrypted = @session.decrypt(:RSA_PKCS, priv_key, encrypted)
    assert_equal(message, decrypted)    
  end
  
  def test_sign_verify_rsa
    pub_key, priv_key = test_generate_rsa_key_pair
    data = "Text to sign/verify using RSA keys"
    signature = @session.sign(:SHA512_RSA_PKCS, priv_key, data)
    @session.verify(:SHA512_RSA_PKCS, pub_key, signature, data)
  end
  
  def generate_aes_key(label)
    label = "Ruby AES Key"
    destroy_object(@session, label)
    key = @session.generate_key(:AES_KEY_GEN,
      :CLASS=>CKO_SECRET_KEY, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
      :TOKEN=>true, :EXTRACTABLE=>true, :VALUE_LEN=>32, :LABEL=>label)
    
    return key
  end
  
  def test_wrap_unwrap
    pub_key, priv_key = test_generate_rsa_key_pair
        
    aes_key = generate_aes_key("Wrapped AES Key")
        
    wrapped = @session.wrap_key(:RSA_PKCS, pub_key, aes_key)
    
    label = "Unwrapped AES Key"
    destroy_object(@session, label)
    
    attributes = {:CLASS=>CKO_SECRET_KEY, :KEY_TYPE=>CKK_AES, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
    :TOKEN=>true, :VALUE_LEN=>32, :LABEL=>label}
    
    unwrapped_key = @session.unwrap_key(:RSA_PKCS, priv_key, wrapped, attributes)
    
    message = "Encrypt/Decrypt with a wrapped and unwrapped key"
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
    cipher_text = @session.encrypt({:AES_CBC_PAD=>iv}, aes_key, message)
    decrypted_text = @session.decrypt({:AES_CBC_PAD=>iv}, unwrapped_key, cipher_text)
    assert_equal(message, decrypted_text)
  end
  
  def test_digest
    data = "Data to digest."
    digest = @session.digest(:SHA512, data)
    hex = digest.bytes.map { |b| sprintf("%02X",b) }.join
    assert_equal(hex, "B22A958E549B113FEC7FE2FBDE766A88D44E34FA47F3EED9DCBA9294AC46DA0CB2511F38943D1F1A533EB25C177F0FC38F2EFC87215D9043F67A103E849A2605")    
  end
  
  def test_des3_cmac_general
    label = "DES Key"
    destroy_object(@session, label)
    des_key = @session.generate_key(:DES3_KEY_GEN,
          :CLASS=>CKO_SECRET_KEY, :SIGN=>true, :VERIFY=>true, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>true, 
          :TOKEN=>true, :EXTRACTABLE=>true, :LABEL=>label)
          
    data = "Data to be signed."
    signature = @session.sign({:DES3_CMAC_GENERAL=>8}, des_key, data)
    @session.verify({:DES3_CMAC_GENERAL=>8}, des_key, signature, data)      
  end
  
  def get_data
    plaintext = ""
    (0..10000).each do |i|
      plaintext << (i%26+65).chr
    end
    plaintext
  end
  
  def test_encrypt_decrypt_multipart
    key = generate_aes_key("Ruby AES Key")
    
    iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16].pack('C*')
    mechanism = {:AES_CBC_PAD=>iv}
    
    chunk_size = 1024
    plaintext = get_data
    
    encrypted = ""
    index = 0
    encrypted << @session.encrypt(mechanism, key) do |cipher|
      while index < plaintext.size
        s = plaintext.slice(index, chunk_size)
        encrypted << cipher.update(s)
        index += chunk_size
      end
    end
    
    decrypted = ""
    index = 0
    decrypted << @session.decrypt(mechanism, key) do |cipher|
      while index < encrypted.size
        s = encrypted.slice(index, chunk_size)
        decrypted << cipher.update(s) 
        index += chunk_size
      end
    end
    assert plaintext == decrypted    
  end
  
  def test_sign_verify
    pub_key, priv_key = test_generate_rsa_key_pair
    
    plaintext = get_data    
    
    signature = @session.sign(:SHA512_RSA_PKCS, priv_key) {|c|
      index = 0
      while index < plaintext.size
        c.update(plaintext.slice(index, 256))
        index += 256
      end
    }
    
    @session.verify(:SHA512_RSA_PKCS, pub_key, signature) {|c|
      index = 0
      while index < plaintext.size
        c.update(plaintext.slice(index, 256))
        index += 256
      end
    }    
  end
  
  def test_digest_encrypt_decrypt_update
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_DigestEncryptUpdate("Not supported")
    }
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_DecryptDigestUpdate("Not supported")
    }
  end
  
  def test_verify_recover
    pub_key, priv_key = test_generate_rsa_key_pair
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_VerifyRecoverInit(:SHA512_RSA_PKCS, pub_key)
    }
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_VerifyRecover("Not supported")
    }
  end
  
  def test_sign_verify_encrypt_decrypt_update
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_SignEncryptUpdate("Not supported")
    }
    assert_raises(CKR_FUNCTION_NOT_SUPPORTED) {
      @session.C_DecryptVerifyUpdate("Not supported")
    }
  end
  
end