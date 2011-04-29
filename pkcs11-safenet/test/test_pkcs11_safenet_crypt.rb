require "test/unit"
require "pkcs11_safenet"
require "test/helper"

class TestPkcs11SafenetCrypt < Test::Unit::TestCase
  include PKCS11
  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  attr_reader :secret_key

  def setup
    $pkcs11 ||= open_ctsw
    @slots = pk.active_slots
    @slot = slots.first

    # Init SO-PIN if not already done.
    if slot.token_info.flags & CKF_TOKEN_INITIALIZED == 0
      slot.init_token('1234', 'test-token')
      assert_match(/^test-token/, slot.token_info.label, "Token label should be set now")
    end
    assert_equal CKF_TOKEN_INITIALIZED, slot.token_info.flags & CKF_TOKEN_INITIALIZED, "Token should be initialized"

    # Init USER-PIN if not already done.
    if slot.token_info.flags & CKF_USER_PIN_INITIALIZED == 0
      s = slot.open(CKF_SERIAL_SESSION | CKF_RW_SESSION)
      assert_equal CKF_RW_SESSION, s.info.flags & CKF_RW_SESSION, "Session should be read/write"
      assert_equal CKS_RW_PUBLIC_SESSION, s.info.state, "Session should be in logoff state"
      s.login(:SO, '1234')
      assert_equal CKS_RW_SO_FUNCTIONS, s.info.state, "Session should be in SO state"
      s.init_pin('1234')
      s.close
    end
    assert_equal CKF_USER_PIN_INITIALIZED, slot.token_info.flags & CKF_USER_PIN_INITIALIZED, "User PIN should be initialized"

    @session = slot.open
    assert_equal CKS_RO_PUBLIC_SESSION, session.info.state, "Session should be in logoff state"
    session.login(:USER, ENV['CRYPTOKI_PIN'] || '1234')
    assert_equal CKS_RO_USER_FUNCTIONS, session.info.state, "Session should be in USER state"

    @secret_key = session.create_object(
      :CLASS=>CKO_SECRET_KEY,
      :KEY_TYPE=>CKK_DES2,
      :ENCRYPT=>true, :WRAP=>true, :DECRYPT=>true, :UNWRAP=>true, :TOKEN=>false, :DERIVE=>true,
      :USAGE_COUNT=>0, :EXPORTABLE=>true,
      :VALUE=>adjust_parity("0123456789abcdef"),
      :LABEL=>'test_secret_key')
  end

  def teardown
    @secret_key.destroy
    @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_bad_parity
    assert_raise(Safenet::CKR_ET_NOT_ODD_PARITY) do
      session.create_object(
        :CLASS=>CKO_SECRET_KEY,
        :KEY_TYPE=>CKK_DES2,
        :VALUE=>"0123456789abcdef",
        :LABEL=>'test_secret_key2')
    end
  end

  def test_derive_des_cbc
    pa = Safenet::CK_DES3_CBC_PARAMS.new
    pa.data = "1"*16
    pa.iv = "2"*8

    new_key1 = session.derive_key( {Safenet::CKM_DES3_DERIVE_CBC => pa}, secret_key,
      :CLASS=>CKO_SECRET_KEY, :KEY_TYPE=>CKK_DES2, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>false )
    assert_not_equal secret_key[:VALUE], new_key1[:VALUE], 'Derived key shouldn\'t have equal key value'

    new_key2 = session.derive_key( {:DES3_DERIVE_CBC => {:data=>"1"*16, :iv=>"2"*16}}, secret_key,
      :CLASS=>CKO_SECRET_KEY, :KEY_TYPE=>CKK_DES2, :ENCRYPT=>true, :DECRYPT=>true, :SENSITIVE=>false )
    assert_equal new_key1[:VALUE], new_key2[:VALUE], 'Both derived key should be equal'

    encrypted_key_value = session.encrypt( {:DES3_CBC => "2"*8}, secret_key, "1"*16)
    encrypted_key_value = adjust_parity(encrypted_key_value)
    assert_equal new_key1[:VALUE], encrypted_key_value, 'Encrypted data should equal derived key value'

    assert_equal 3, secret_key[:USAGE_COUNT], 'The secret key should be used 3 times'
  end


  def test_attributes
    assert_equal true, secret_key[:EXPORTABLE], 'CKA_EXTRACTABLE should be usable'
    secret_key[:EXPORTABLE] = false
    assert_equal false, secret_key[:EXPORTABLE], 'CKA_EXTRACTABLE should be usable'

    assert_equal 0, secret_key[:USAGE_COUNT], 'CKA_USAGE_COUNT should be usable'
    secret_key[:USAGE_COUNT] = 5
    assert_equal 5, secret_key[:USAGE_COUNT], 'CKA_USAGE_COUNT should be usable'

    assert_equal false, secret_key[:IMPORT], 'CKA_IMPORT should default to false'
  end
end
