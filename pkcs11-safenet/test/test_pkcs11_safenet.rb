require "test/unit"
require "pkcs11_safenet"
require "test/helper"

class TestPkcs11Safenet < Test::Unit::TestCase
  include PKCS11

  def test_CStruct
    s = Safenet::CK_SECRET_SHARE_PARAMS.new
    s.n, s.m = 2, 3

    assert_match( /m=3/, s.inspect, 'There should be a n value in CK_SECRET_SHARE_PARAMS')
    assert_equal ["n", "m"], s.members, 'CK_SECRET_SHARE_PARAMS should contain some attributes'
    assert_equal [2, 3], s.values, 'values of CK_SECRET_SHARE_PARAMS'
    assert_equal( {:n=>2, :m=>3}, s.to_hash, 'CK_SECRET_SHARE_PARAMS as hash' )
  end

  def test_CK_PKCS12_PBE_IMPORT_PARAMS
    s = Safenet::CK_PKCS12_PBE_IMPORT_PARAMS.new
    assert_equal [], s.certAttr
    s1 = CK_ATTRIBUTE.new Safenet::CKA_EXPORT, true
    s2 = CK_ATTRIBUTE.new Safenet::CKA_EXPORTABLE, false
    s.certAttr = [s1, s2]
    assert_equal [s1.to_hash, s2.to_hash], s.certAttr.map{|e| e.to_hash }
    GC.start
    assert_raise(ArgumentError){ s.certAttr = [s1, s2, nil] }
    assert_equal [s1.to_hash, s2.to_hash], s.certAttr.map{|e| e.to_hash }

    s.certAttr = []
    assert_equal [], s.certAttr
  end

  def test_constants
    assert_equal 0x80000990, Safenet::CKM_OS_UPGRADE, "CKM_OS_UPGRADE should be defined"
    assert_equal 0x80000128, Safenet::CKA_EXPORT, "CKA_EXPORT should be defined"
    assert_equal 0x80000129, Safenet::CKA_EXPORTABLE, "CKA_EXPORTABLE should be defined"
    assert Safenet::CKR_ET_NOT_ODD_PARITY.ancestors.include?(PKCS11::Error), "CKR_ET_NOT_ODD_PARITY should be defined"
    assert_equal 0x8000020c, Safenet::CKO_FM, "CKO_FM should be defined"
  end

  def test_loading
    pk = PKCS11::Safenet::Library.new(:sw, :flags=>0)
    so_path = pk.so_path
    pk.close
    assert !so_path.empty?, "Used path shouldn't be empty"

    pk = PKCS11::Safenet::Library.new(so_path, :flags=>0)
    pk.close
  end
end
