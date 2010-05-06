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
    signature = session.sign( :RSA_PKCS, rsa_priv_key, "important text")
    assert 'The signature should contain some data', signature.length>10
    
    valid = session.verify( :RSA_PKCS, rsa_pub_key, signature, "important text")
    assert 'The signature should be correct', valid
    
    assert_raise(PKCS11::Error) do
      session.verify( :RSA_PKCS, rsa_pub_key, signature, "modified text")
    end
  end

end
