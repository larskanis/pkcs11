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
    assert_equal 1, object.attributes(:VALUE).length, 'There should be one resulting attribute'
    assert_equal CK_ATTRIBUTE, object.attributes(:VALUE).first.class, 'Resulting attribute should be type CK_ATTRIBUTE'
    assert_equal CKO_DATA, object.attributes(:CLASS).first.value, 'Resulting attribute should be Integer value CKO_DATA'
    assert_equal 3, object.attributes(:VALUE, :TOKEN, :PRIVATE).length, 'An object should have some attributes'
    assert_equal 3, object.attributes([:VALUE, :TOKEN, :APPLICATION]).length, 'Another way to retieve attributes'
    assert_equal 2, object.attributes(:VALUE=>nil, :TOKEN=>nil).length, 'Third way to retieve attributes'

    # The C language way to retrieve the attribute values:
    template = [
      CK_ATTRIBUTE.new(CKA_VALUE, nil),
    ]
    attrs = pk.C_GetAttributeValue(session, object, template)
    attrs.each do |attr|
      assert attr.value, 'There should be a value to the object'
    end

    assert object.attributes.length>=4, 'There should be at least the 4 stored attributes readable'
  end

  def test_accessor
    assert_equal 'value', object[:VALUE], "Value should be readable"
    assert_equal CKO_DATA, object[:CLASS], "Class should be readable"
  end

  def test_attribute
    attr = object.attributes(:CLASS).first
    assert attr.inspect =~ /CLASS/, 'The attribute should tell about it\'s type'
    assert attr.inspect =~ /#{CKO_DATA}/, 'The attribute should tell about it\'s type'
  end

  def test_set_attribute
    object[:VALUE] = 'value2'
    assert_equal 'value2', object[:VALUE], "Value should have changed"
  end

  def test_set_attributes
    object.attributes = {:VALUE => 'value2', PKCS11::CKA_APPLICATION => 'app2'}

    assert_equal 'value2', object[:VALUE], "Value should have changed"
    assert_equal 'app2', object[:APPLICATION], "App should have changed"
  end

  def test_size
    assert object.size, 'There should be an object size'
  end
  
  def test_destroy
    object.destroy
    
    assert_raise(PKCS11::Error, 'destroyed object shouldn\'t have any attributes') do
      object[:VALUE]
    end
  end
end
