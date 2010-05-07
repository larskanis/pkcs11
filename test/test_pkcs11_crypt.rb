require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Session < Test::Unit::TestCase
  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  attr_reader :rsa_priv_key
  attr_reader :rsa_pub_key

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    
    flags = PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION
    @session = slot.C_OpenSession(flags)
    session.login(PKCS11::CKU_USER, "")
    
    @rsa_pub_key = session.find_objects(:CLASS => PKCS11::CKO_PUBLIC_KEY,
                        :KEY_TYPE => PKCS11::CKK_RSA).first
    @rsa_priv_key = session.find_objects(:CLASS => PKCS11::CKO_PRIVATE_KEY,
                        :KEY_TYPE => PKCS11::CKK_RSA).first
  end

  def teardown
    @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_endecrypt
    plaintext1 = "secret text"
    cryptogram = session.encrypt( :RSA_PKCS, rsa_pub_key, plaintext1)
    assert 'The cryptogram should contain some data', cryptogram.length>10
    assert 'The cryptogram should be different to plaintext', cryptogram != plaintext1
    
    plaintext2 = session.decrypt( :RSA_PKCS, rsa_priv_key, cryptogram)
    assert 'Decrypted plaintext should be the same', plaintext1==plaintext2
  end

  def test_sign_verify
    plaintext = "important text"
    signature = session.sign( :SHA1_RSA_PKCS, rsa_priv_key, plaintext)
    assert 'The signature should contain some data', signature.length>10
    assert 'The signature should contain some data', signature.length>10

    signature2 = session.sign( :SHA1_RSA_PKCS, rsa_priv_key){|c|
      c.update(plaintext[0..3])
      c.update(plaintext[4..-1])
    }
    assert_equal signature, signature2, 'results of one-step and two-step signatures should be equal'

    valid = session.verify( :SHA1_RSA_PKCS, rsa_pub_key, signature, plaintext)
    assert 'The signature should be correct', valid
    
    assert_raise(PKCS11::Error, 'The signature should be invalid on different text') do
      session.verify( :SHA1_RSA_PKCS, rsa_pub_key, signature, "modified text")
    end
  end

  def create_openssl_cipher(pk11_key)
    rsa = OpenSSL::PKey::RSA.new
    rsa.n = OpenSSL::BN.new pk11_key[:MODULUS], 2
    rsa.e = OpenSSL::BN.new pk11_key[:PUBLIC_EXPONENT], 2
    rsa
  end

  def test_compare_sign_with_openssl
    signature = session.sign( :SHA1_RSA_PKCS, rsa_priv_key, "important text")

    osslc = create_openssl_cipher rsa_pub_key
    valid = osslc.verify(OpenSSL::Digest::SHA1.new, signature, "important text")
    assert 'The signature should be correct', valid
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
  end

end
