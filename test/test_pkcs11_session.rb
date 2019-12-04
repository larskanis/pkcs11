require "minitest/autorun"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Session < Minitest::Test
  include PKCS11

  attr_reader :slots
  attr_reader :slot
  attr_reader :session

  TestCert_ID = "\230Z\275=\2614\236\337\fY\017Y\346\202\212\v\025\335\0239"

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last

    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    @session = slot.C_OpenSession(flags)
#     @session.login(:USER, "")
  end

  def teardown
#     @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_find_objects
    obj = session.find_objects(CLASS:  CKO_CERTIFICATE)
    assert obj.length>2, 'There should be some certificates in the test database'
    assert_equal PKCS11::Object, obj.first.class, 'Retuned objects should be class Object'

    session.find_objects(CLASS:  CKO_CERTIFICATE) do |obj2|
      assert obj2[:SUBJECT], 'A certificate should have a subject'
      assert OpenSSL::X509::Name.new(obj2[:SUBJECT]).to_s =~ /\/CN=/i, 'Every certificate should have a CN in the subject'
    end
  end

  def test_random
    session.seed_random('some entropy')
    rnd1 = session.generate_random(13)
    assert_equal rnd1.length, 13, 'expected length'
    rnd2 = session.generate_random(13)
    assert_equal rnd2.length, 13, 'expected length'
    refute_equal rnd1, rnd2, 'Two random blocks should be different'
  end

  def test_session_info
    info = session.info
    assert info.inspect =~ /flags=/, 'Session info should have a flag attribute'
  end

  def test_create_data_object
    _obj = session.create_object(
      CLASS: CKO_DATA,
      TOKEN: false,
      APPLICATION: 'My Application',
      VALUE: 'value')
  end

  def test_create_certificate_object
    obj1 = session.find_objects(CLASS:  CKO_CERTIFICATE, ID: TestCert_ID).first

    obj = session.create_object(
      CLASS: CKO_CERTIFICATE,
      SUBJECT: obj1[:SUBJECT],
      TOKEN: false,
      LABEL: 'test_create_object',
      CERTIFICATE_TYPE: CKC_X_509,
      ISSUER: obj1[:ISSUER],
      VALUE: obj1[:VALUE],
      SERIAL_NUMBER: '12345'
    )

    assert_equal '12345', obj[:SERIAL_NUMBER], 'Value as created'
  end

  def test_create_public_key_object
    rsa = OpenSSL::PKey::RSA.generate(512)

    obj = session.create_object(
      CLASS: CKO_PUBLIC_KEY,
      KEY_TYPE: CKK_RSA,
      TOKEN: false,
      MODULUS: rsa.n.to_s(2),
      PUBLIC_EXPONENT: rsa.e.to_s(2),
      LABEL: 'test_create_public_key_object')

    assert_equal 'test_create_public_key_object', obj[:LABEL], 'Value as created'
  end

  def test_get_set_operation_state
    plaintext = "secret text"

    # Start a digest operation
    session.C_DigestInit(:SHA_1)
    session.C_DigestUpdate(plaintext[0..3])

    # Save the current state and close the session
    state = session.get_operation_state
    @session.close

    assert state.length >= 4, 'There should be at least some bytes for the first part of plaintext in the state'

    # Open a new session and restore the previous state
    @session = @slot.open
    session.login(:USER, "")
    session.set_operation_state(state)

    # Finish the digest
    session.C_DigestUpdate(plaintext[4..-1])
    digest1 = session.C_DigestFinal
    digest2 = OpenSSL::Digest::SHA1.new(plaintext).digest

    assert_equal digest2, digest1, 'Digests should be equal'
  end
end
