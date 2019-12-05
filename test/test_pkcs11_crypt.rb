require "minitest/autorun"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Crypt < Minitest::Test
  include PKCS11

  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  attr_reader :rsa_priv_key
  attr_reader :rsa_pub_key
  attr_reader :secret_key

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    @session = slot.open
#     session.login(:USER, "")

    @rsa_pub_key = session.find_objects(CLASS:  CKO_PUBLIC_KEY,
                        KEY_TYPE:  CKK_RSA).first
    @rsa_priv_key = session.find_objects(CLASS:  CKO_PRIVATE_KEY,
                        KEY_TYPE:  CKK_RSA).first
    @secret_key = session.create_object(
      CLASS: CKO_SECRET_KEY,
      KEY_TYPE: CKK_DES2,
      ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true, TOKEN: false,
      VALUE: '0123456789abcdef',
      LABEL: 'test_secret_key')
  end

  def teardown
    @secret_key.destroy
#     @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_endecrypt_rsa
    plaintext1 = "secret text"
    cryptogram = session.encrypt( :RSA_PKCS, rsa_pub_key, plaintext1)
    assert cryptogram.length>10, 'The cryptogram should contain some data'
    refute_equal cryptogram, plaintext1, 'The cryptogram should be different to plaintext'

    plaintext2 = session.decrypt( :RSA_PKCS, rsa_priv_key, cryptogram)
    assert_equal plaintext1, plaintext2, 'Decrypted plaintext should be the same'
  end

  def test_endecrypt_des
    plaintext1 = "secret message "
    cryptogram = session.encrypt( {DES3_CBC_PAD: "\0"*8}, secret_key, plaintext1)
    assert_equal 16, cryptogram.length, 'The cryptogram should contain some data'
    refute_equal cryptogram, plaintext1, 'The cryptogram should be different to plaintext'

    cryptogram2 = ''
    cryptogram2 << session.encrypt( {DES3_CBC_PAD: "\0"*8}, secret_key ) do |cipher|
      cryptogram2 << cipher.update(plaintext1[0, 8])
      cryptogram2 << cipher.update(plaintext1[8..-1])
    end
    assert_equal cryptogram, cryptogram2, "Encrypt with and w/o block should be lead to the same result"

    plaintext2 = session.decrypt( {DES3_CBC_PAD: "\0"*8}, secret_key, cryptogram)
    assert_equal plaintext1, plaintext2, 'Decrypted plaintext should be the same'
  end

  def test_sign_verify
    plaintext = "important text"
    signature = session.sign( :SHA1_RSA_PKCS, rsa_priv_key, plaintext)
    assert signature.length>10, 'The signature should contain some data'

    signature2 = session.sign( :SHA1_RSA_PKCS, rsa_priv_key){|c|
      c.update(plaintext[0..3])
      c.update(plaintext[4..-1])
    }
    assert_equal signature, signature2, 'results of one-step and two-step signatures should be equal'

    valid = session.verify( :SHA1_RSA_PKCS, rsa_pub_key, signature, plaintext)
    assert  valid, 'The signature should be correct'

    assert_raises(CKR_SIGNATURE_INVALID, 'The signature should be invalid on different text') do
      session.verify( :SHA1_RSA_PKCS, rsa_pub_key, signature, "modified text")
    end
  end

  def create_openssl_cipher(pk11_key)
    rsa = OpenSSL::PKey::RSA.new
    n = OpenSSL::BN.new pk11_key[:MODULUS], 2
    e = OpenSSL::BN.new pk11_key[:PUBLIC_EXPONENT], 2
    if rsa.respond_to?(:set_key)
      rsa.set_key(n, e, nil)
    else
      rsa.n = n
      rsa.e = e
    end
    rsa
  end

  def test_compare_sign_with_openssl
    signature = session.sign( :SHA1_RSA_PKCS, rsa_priv_key, "important text")

    osslc = create_openssl_cipher rsa_pub_key
    valid = osslc.verify(OpenSSL::Digest::SHA1.new, signature, "important text")
    assert valid, 'The signature should be correct'
  end

  def test_compare_endecrypt_with_openssl
    plaintext1 = "secret text"
    osslc = create_openssl_cipher rsa_pub_key
    cryptogram = osslc.public_encrypt(plaintext1)

    plaintext2 = session.decrypt( :RSA_PKCS, rsa_priv_key, cryptogram)
    assert_equal plaintext1, plaintext2, 'Decrypted plaintext should be the same'
  end

  def test_digest
    plaintext = "secret text"
    digest1 = session.digest( :SHA_1, plaintext)
    digest2 = OpenSSL::Digest::SHA1.new(plaintext).digest
    assert_equal digest1, digest2, 'Digests should be equal'
    digest3 = session.digest(:SHA_1){|c|
      c.update(plaintext[0..3])
      c.update(plaintext[4..-1])
    }
    assert_equal digest1, digest3, 'Digests should be equal'

    digest3 = session.digest(:SHA256){|c|
      c.update(plaintext)
      c.digest_key(secret_key)
    }
  end

  def test_wrap_key
    wrapped_key_value = session.wrap_key(:DES3_ECB, secret_key, secret_key)
    assert_equal 16, wrapped_key_value.length, '112 bit 3DES key should have same size wrapped'

    unwrapped_key = session.unwrap_key(:DES3_ECB, secret_key, wrapped_key_value, CLASS: CKO_SECRET_KEY, KEY_TYPE: CKK_DES2, ENCRYPT: true, DECRYPT: true)

    secret_key_kcv = session.encrypt( :DES3_ECB, secret_key, "\0"*8)
    unwrapped_key_kcv = session.encrypt( :DES3_ECB, unwrapped_key, "\0"*8)
    assert_equal secret_key_kcv, unwrapped_key_kcv, 'Key check values of original and wrapped/unwrapped key should be equal'
  end

  def test_wrap_private_key
    wrapped_key_value = session.wrap_key({DES3_CBC_PAD: "\0"*8}, secret_key, rsa_priv_key)
    assert wrapped_key_value.length>100, 'RSA private key should have bigger size wrapped'
  end

  def test_generate_secret_key
    key = session.generate_key(:DES2_KEY_GEN,
      {ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true, TOKEN: false, LOCAL: true})
    assert_equal true, key[:LOCAL], 'Keys created on the token should be marked as local'
    assert_equal CKK_DES2, key[:KEY_TYPE], 'Should be a 2 key 3des key'

		# other ways to use mechanisms
    key = session.generate_key(CKM_DES2_KEY_GEN,
      {ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true, TOKEN: false, LOCAL: true})
    assert_equal CKK_DES2, key[:KEY_TYPE], 'Should be a 2 key 3des key'
    key = session.generate_key(CK_MECHANISM.new(CKM_DES2_KEY_GEN, nil),
      {ENCRYPT: true, WRAP: true, DECRYPT: true, UNWRAP: true, TOKEN: false, LOCAL: true})
    assert_equal CKK_DES2, key[:KEY_TYPE], 'Should be a 2 key 3des key'
  end

  def test_generate_key_pair
    pub_key, priv_key = session.generate_key_pair(:RSA_PKCS_KEY_PAIR_GEN,
      {ENCRYPT: true, VERIFY: true, WRAP: true, MODULUS_BITS: 768, PUBLIC_EXPONENT: [65537].pack("N"), TOKEN: false},
      {PRIVATE: true, SUBJECT: 'test', ID: [123].pack("n"),
       SENSITIVE: true, DECRYPT: true, SIGN: true, UNWRAP: true, TOKEN: false, LOCAL: true})

    assert_equal true, priv_key[:LOCAL], 'Private keys created on the token should be marked as local'
    assert_equal priv_key[:CLASS], CKO_PRIVATE_KEY
    assert_equal pub_key[:CLASS], CKO_PUBLIC_KEY
    assert_equal true, priv_key[:SENSITIVE], 'Private key should be sensitive'
  end

  def test_derive_key
    # Generate DH key for side 1
    key1 = OpenSSL::PKey::DH.new(512)

    # Generate key side 2 with same prime and base as side 1
    pub_key2, priv_key2 = session.generate_key_pair(:DH_PKCS_KEY_PAIR_GEN,
      {PRIME: key1.p.to_s(2), BASE: key1.g.to_s(2), TOKEN: false},
      {VALUE_BITS: 512, DERIVE: true, TOKEN: false})

    # Derive secret DES key for side 1 with OpenSSL
    new_key1 = key1.compute_key(OpenSSL::BN.new pub_key2[:VALUE], 2)

    # Derive secret DES key for side 2 with softokn3
    new_key2 = session.derive_key( {DH_PKCS_DERIVE: key1.pub_key.to_s(2)}, priv_key2,
      CLASS: CKO_SECRET_KEY, KEY_TYPE: CKK_AES, VALUE_LEN: 16, ENCRYPT: true, DECRYPT: true, SENSITIVE: false )

    # Some versions of softokn3 use left- and some use rightmost bits of exchanged key
    assert_operator [new_key1[0,16], new_key1[-16..-1]], :include?, new_key2[:VALUE], 'Exchanged session key should be equal'
  end

  def test_derive_key2
    deriv_data = "\0"*16
    new_key1 = session.derive_key( {CKM_XOR_BASE_AND_DATA => {pData:  deriv_data}}, secret_key,
      CLASS: CKO_SECRET_KEY, KEY_TYPE: CKK_AES, VALUE_LEN: 16, ENCRYPT: true, DECRYPT: true, SENSITIVE: false )

    assert_equal secret_key[:VALUE], new_key1[:VALUE], 'Derived key should have equal key value'
  end

  def test_ssl3
    pm_key = session.generate_key({SSL3_PRE_MASTER_KEY_GEN:  {major: 3, minor: 0}},
        {TOKEN: false})
    assert_equal 48, pm_key[:VALUE_LEN], "SSL3 pre master key should be 48 bytes long"

    dp = CK_SSL3_MASTER_KEY_DERIVE_PARAMS.new
    dp.RandomInfo.pServerRandom = 'srandom ' * 4
    dp.RandomInfo.pClientRandom = 'crandom ' * 4
    dp.pVersion = CK_VERSION.new
    dp.pVersion.major = 3
    dp.pVersion.minor = 1
    ms_key = session.derive_key( {CKM_SSL3_MASTER_KEY_DERIVE => dp}, pm_key )

    assert_equal 48, ms_key[:VALUE_LEN], "SSL3 master secret key should be 48 bytes long"
    assert_equal 0, dp.pVersion.minor, 'SSL3 version number should have changed'
  end

end
