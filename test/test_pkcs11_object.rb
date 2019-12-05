require "minitest/autorun"
require "pkcs11"
require "test/helper"

class TestPkcs11Object < Minitest::Test
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
#     @session.login(:USER, "")

    # Create session object for tests.
    @object = session.create_object(
      CLASS: CKO_DATA,
      TOKEN: false,
      APPLICATION: 'My Application',
      VALUE: 'value')
  end

  def teardown
#     @session.logout
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
    assert_equal 2, object.attributes(VALUE: nil, TOKEN: nil).length, 'Third way to retieve attributes'

    # The C language way to retrieve the attribute values:
    template = [
      CK_ATTRIBUTE.new(CKA_VALUE, nil),
    ]
    attrs = pk.C_GetAttributeValue(session, object, template)
    attrs.each do |attr|
      assert attr.value, 'There should be a value to the object'
    end

    assert object.attributes.length>=4, 'There should be at least the 4 stored attributes readable'
    refute_nil object.attributes.find{|a| a.type==CKA_CLASS}, 'CKA_CLASS should be returned for Object#attributes'
  end

  def test_accessor
    assert_equal 'value', object[:VALUE], "Value should be readable"
    assert_equal Encoding::BINARY, object[:VALUE].encoding
    assert_equal 'My Application', object[:APPLICATION]
    assert_equal Encoding::UTF_8, object[:APPLICATION].encoding
    assert_equal CKO_DATA, object[:CLASS], "Class should be readable"
    assert_equal ['value', CKO_DATA], object[:VALUE, :CLASS], "multiple values should be readable"
    assert_equal ['value', CKO_DATA], object[[:VALUE, :CLASS]], "multiple values should be readable"
    assert_equal [], object[[]], "multiple values should be readable"
  end

  def test_attribute
    attr = object.attributes(:CLASS).first
    assert attr.inspect =~ /CLASS/, 'The attribute should tell about it\'s type'
    assert attr.inspect =~ /#{CKO_DATA}/, 'The attribute should tell about it\'s type'
  end

  def test_set_attribute
    object[:VALUE] = 'value2'
    assert_equal 'value2', object[:VALUE], "Value should have changed"

    object[:VALUE] = ['value3']
    assert_equal 'value3', object[:VALUE], "Value should have changed"
  end

  def test_set_attributes
    object.attributes = {VALUE:  'value4', PKCS11::CKA_APPLICATION => 'Äpp4'}
    assert_equal 'value4', object[:VALUE], "Value should have changed"
    assert_equal 'Äpp4', object[:APPLICATION], "App should have changed"

    object[:VALUE, PKCS11::CKA_APPLICATION] = 'value5', 'äpp5'
    assert_equal 'value5', object[:VALUE], "Value should have changed"
    assert_equal 'äpp5', object[:APPLICATION], "App should have changed"
    assert_raises(ArgumentError) do
      object[:VALUE, PKCS11::CKA_APPLICATION, :CLASS] = 'value5', 'äpp5'
    end

    object[] = []
  end

  def test_size
    assert object.size, 'There should be an object size'
  end

  def test_copy_without_params
    new_obj = object.copy
    new_obj[:APPLICATION] = 'Copied object'
    assert_equal 'Copied object', new_obj[:APPLICATION], "Application should be changed"
    assert_equal 'My Application', object[:APPLICATION], "Original object should be unchanged"
  end

  def test_copy_with_params
    new_obj = object.copy APPLICATION: 'Copied object'
    assert_equal 'value', new_obj[:VALUE], "Value should be copied"
    assert_equal 'Copied object', new_obj[:APPLICATION], "Application should be changed"
    assert_equal 'My Application', object[:APPLICATION], "Original object should be unchanged"
  end

  def test_destroy
    object.destroy

    assert_raises(CKR_OBJECT_HANDLE_INVALID, 'destroyed object shouldn\'t have any attributes') do
      object[:VALUE]
    end
  end
end
