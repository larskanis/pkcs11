require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Session < Test::Unit::TestCase
  attr_reader :slots
  attr_reader :slot
  attr_reader :session

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    
    flags = PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION
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

  def test_find_with_block
    session.find_objects(:CLASS => PKCS11::CKO_CERTIFICATE) do |obj|
      assert 'A certificate should have some attributes', obj.attributes([:SUBJECT, :ID]).length == 2
      
      assert 'Every certificate should have a CN in the subject', OpenSSL::X509::Name.new(obj[:SUBJECT]) =~ /\/CN=/i

      # another way to retrieve the attribute values:
      template = [
        PKCS11::CK_ATTRIBUTE.new(PKCS11::CKA_SUBJECT, nil),
      ]
      attrs = pk.C_GetAttributeValue(session, obj, template)
      attrs.each do |attr|
        assert 'Every certificate should have a CN in the subject', OpenSSL::X509::Name.new(attr.value) =~ /\/CN=/i
      end
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
end
