require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Session < Test::Unit::TestCase
  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  
  TestCert_ID = "\230Z\275=\2614\236\337\fY\017Y\346\202\212\v\025\335\0239"

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    
    flags = PKCS11::CKF_SERIAL_SESSION #| PKCS11::CKF_RW_SESSION
    @session = slot.C_OpenSession(flags)
    @session.login(:USER, "")
  end

  def teardown
    @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_find_objects
    obj = session.find_objects(:CLASS => PKCS11::CKO_CERTIFICATE)
    assert 'There should be some certificates in the test database', obj.length>10
    assert_equal PKCS11::Object, obj.first.class, 'Retuned objects should be class Object'
    
    session.find_objects(:CLASS => PKCS11::CKO_CERTIFICATE) do |obj|
      assert 'A certificate should have a subject', obj[:SUBJECT]
      assert 'Every certificate should have a CN in the subject', OpenSSL::X509::Name.new(obj[:SUBJECT]) =~ /\/CN=/i
    end
  end

  def test_random
    session.seed_random('some entropy')
    rnd1 = session.generate_random(13)
    assert_equal rnd1.length, 13, 'expected length'
    rnd2 = session.generate_random(13)
    assert_equal rnd2.length, 13, 'expected length'
    assert_not_equal rnd1, rnd2, 'Two random blocks should be different'
  end

  def test_session_info
    info = session.info
    assert 'Session info should have a flag attribute', info =~ /flags=/
  end
  
  def test_create_data_object
    obj = session.create_object(
      :CLASS=>PKCS11::CKO_DATA,
      :TOKEN=>false,
      :APPLICATION=>'My Application',
      :VALUE=>'value')
  end
  
  def test_create_certificate_object
    obj1 = session.find_objects(:CLASS => PKCS11::CKO_CERTIFICATE, :ID=>TestCert_ID).first
#     PKCS11::ATTRIBUTES.values.each{|attr|
#       p [attr, obj1[attr.gsub('CKA_','')]] rescue PKCS11::Error
#     }

    obj = session.create_object(
      :CLASS=>PKCS11::CKO_CERTIFICATE,
      :SUBJECT=>obj1[:SUBJECT],
      :TOKEN=>false,
      :LABEL=>'test_create_object',
      :CERTIFICATE_TYPE=>PKCS11::CKC_X_509,
      :ISSUER=>obj1[:ISSUER],
      :VALUE=>obj1[:VALUE],
      :SERIAL_NUMBER=>'12345'
    )
    
    assert_equal '12345', obj[:SERIAL_NUMBER], 'Value as created'
  end
  
  def test_create_public_key_object
    rsa = OpenSSL::PKey::RSA.generate(512)
  
    obj = session.create_object(
      :CLASS=>PKCS11::CKO_PUBLIC_KEY,
      :KEY_TYPE=>PKCS11::CKK_RSA,
      :TOKEN=>false,
      :MODULUS=>rsa.n.to_s(2),
      :PUBLIC_EXPONENT=>rsa.e.to_s(2),
      :LABEL=>'test_create_public_key_object')
    
    assert_equal 'test_create_public_key_object', obj[:LABEL], 'Value as created'
  end
end
