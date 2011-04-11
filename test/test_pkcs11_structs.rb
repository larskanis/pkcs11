require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11Structs < Test::Unit::TestCase
  include PKCS11

  def setup
  end

  def teardown
  end

  def test_STRING_ACCESSOR
    s = CK_DATE.new
    assert_equal "\0\0", s.day
    assert_equal "\0\0\0\0", s.year
    s.day = "12345"
    assert_equal "12", s.day
    s.day = "9"
    assert_equal "9\0", s.day
    assert_raise(TypeError){ s.day = nil }
  end

  def test_ULONG_ACCESSOR
    s = CK_SSL3_KEY_MAT_PARAMS.new
    assert_equal 0, s.ulIVSizeInBits
    s.ulIVSizeInBits = 1234567890
    assert_equal 1234567890, s.ulIVSizeInBits
    s.ulIVSizeInBits = 2345678901
    assert_equal 2345678901, s.ulIVSizeInBits
    assert_raise(TypeError){ s.ulIVSizeInBits = nil }
  end

  def test_BOOL_ACCESSOR
    s = CK_SSL3_KEY_MAT_PARAMS.new
    assert_equal false, s.bIsExport
    s.bIsExport = true
    assert_equal true, s.bIsExport
    s.bIsExport = false
    assert_equal false, s.bIsExport
    assert_raise(ArgumentError){ s.bIsExport = nil }
  end

  def test_STRING_PTR_ACCESSOR
    s = CK_WTLS_MASTER_KEY_DERIVE_PARAMS.new
    assert_nil s.pVersion
    s.pVersion = "1.2.3"
    assert_equal "1.2.3", s.pVersion
    s.pVersion = nil
    assert_nil s.pVersion
  end

  def test_STRUCT_ACCESSOR
    s = CK_SSL3_KEY_MAT_PARAMS.new
    ri = s.RandomInfo
    ro = s.RandomInfo
    assert_nil ri.pClientRandom
    assert_nil ro.pServerRandom
    GC.start
    ri.pServerRandom = 'serv'
    ro.pClientRandom = 'client'
    GC.start
    assert_equal 'client', ri.pClientRandom
    assert_equal 'serv', ro.pServerRandom

    ro = CK_SSL3_RANDOM_DATA.new
    ro.pClientRandom = 'clrnd'
    s.RandomInfo = ro
    assert_equal 'clrnd', ri.pClientRandom
    assert_nil ri.pServerRandom

    assert_raise(ArgumentError){ s.RandomInfo = nil }
  end

  def test_gc_STRUCT_ACCESSOR
    ri = CK_SSL3_KEY_MAT_PARAMS.new.RandomInfo
    ro = CK_SSL3_KEY_MAT_PARAMS.new.RandomInfo
    ri.pServerRandom = 'serv'
    ro.pServerRandom = '_serv'
    GC.start
    assert_equal '_serv', ro.pServerRandom
    assert_equal 'serv', ri.pServerRandom
    assert_nil ro.pClientRandom
    assert_nil ri.pClientRandom
  end

  def test_STRING_PTR_LEN_ACCESSOR
    s = CK_SSL3_RANDOM_DATA.new
    assert_nil s.pServerRandom
    GC.start
    s.pServerRandom = 'serv'
    s.pClientRandom = 'client'
    GC.start
    assert_equal 'client', s.pClientRandom
    assert_equal 'serv', s.pServerRandom
    GC.start
    s.pServerRandom = nil
    assert_nil s.pServerRandom
  end

  def test_STRUCT_PTR_ACCESSOR
    s = CK_SSL3_KEY_MAT_PARAMS.new
    assert_nil s.pReturnedKeyMaterial
    ri = s.pReturnedKeyMaterial = CK_SSL3_KEY_MAT_OUT.new
    assert_nil ri.pIVClient
    ri.pIVClient = 'cli'
    GC.start
    assert_equal 'cli', ri.pIVClient
    assert_equal 'cli', s.pReturnedKeyMaterial.pIVClient
    s.pReturnedKeyMaterial = nil
    assert_nil s.pReturnedKeyMaterial
  end

  def test_ULONG_PTR_ACCESSOR
    s = CK_WTLS_PRF_PARAMS.new
    assert_nil s.pulOutputLen
    s.pulOutputLen = 123
    GC.start
    assert_equal 123, s.pulOutputLen
    s.pulOutputLen = nil
    assert_nil s.pulOutputLen
  end

  def test_STRUCT_ARRAY_ACCESSOR
    s = CK_OTP_PARAMS.new
    assert_equal [], s.pParams
    s1 = CK_OTP_PARAM.new
    s1.type = CK_OTP_VALUE
    s1.pValue = "\0xyz"
    s2 = CK_OTP_PARAM.new
    s2.type = CK_OTP_PIN
    s2.pValue = "1234"
    s.pParams = [s1, s2]
    assert_equal [s1.to_hash, s2.to_hash], s.pParams.map{|e| e.to_hash }
    GC.start
    assert_raise(ArgumentError){ s.pParams = [s1, s2, nil] }
    assert_equal [s1.to_hash, s2.to_hash], s.pParams.map{|e| e.to_hash }
  end

  def test_CStruct
    s = CK_DATE.new
    s.day, s.month, s.year = "31", "12", "2010"

    assert s.inspect =~ /year="2010"/, 'There should be a year in CK_DATE'
    assert_equal ["year", "month", "day"], s.members, 'CK_DATE should contain some attributes'
    assert_equal ["2010", "12", "31"], s.values, 'values of CK_DATE'
    assert_equal( {:day=>"31", :month=>"12", :year=>"2010"}, s.to_hash, 'CK_DATE as hash' )
  end
end
