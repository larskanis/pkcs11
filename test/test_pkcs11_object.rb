require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Object < Test::Unit::TestCase
  include PKCS11

  attr_reader :slots
  attr_reader :slot
  attr_reader :session
  attr_reader :object

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
    
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    @session = slot.C_OpenSession(flags)
    @session.login(:USER, "")
    
    # Create session object for tests.
    @object = session.create_object(
      :CLASS=>CKO_DATA,
      :TOKEN=>false,
      :APPLICATION=>'My Application',
      :VALUE=>'value')
  end

  def teardown
    @session.logout
    @session.close
  end

  def pk
    $pkcs11
  end

  def test_attributes
    assert 'An object should have some attributes', object.attributes(:VALUE, :TOKEN).length == 2
    assert 'Another way to retieve attributes', object.attributes([:VALUE, :TOKEN]).length == 2
    assert 'Third way to retieve attributes', object.attributes(:VALUE=>nil, :TOKEN=>nil).length == 2

    # The C language way to retrieve the attribute values:
    template = [
      CK_ATTRIBUTE.new(CKA_VALUE, nil),
    ]
    attrs = pk.C_GetAttributeValue(session, object, template)
    attrs.each do |attr|
      assert 'There should be a value to the object', attr.value
    end
  end
    
  def test_size
    assert 'There should be an object size', object.size
  end
  
  def test_destroy
    object.destroy
    
    assert_raise(PKCS11::Error, 'destroyed object shouldn\'t have any attributes') do
      object[:VALUE]
    end
  end
end
