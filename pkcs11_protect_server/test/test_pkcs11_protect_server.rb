require "minitest/autorun"
require "pkcs11_protect_server"
require "test/helper"

class TestPkcs11ProtectServer < Minitest::Test
  include PKCS11

  def test_CStruct
    s = ProtectServer::CK_SECRET_SHARE_PARAMS.new
    s.n, s.m = 2, 3

    assert_match( /m=3/, s.inspect, 'There should be a n value in CK_SECRET_SHARE_PARAMS')
    assert_equal ["n", "m"], s.members, 'CK_SECRET_SHARE_PARAMS should contain some attributes'
    assert_equal [2, 3], s.values, 'values of CK_SECRET_SHARE_PARAMS'
    assert_equal( {n: 2, m: 3}, s.to_hash, 'CK_SECRET_SHARE_PARAMS as hash' )
  end

  def test_CK_PKCS12_PBE_IMPORT_PARAMS
    s = ProtectServer::CK_PKCS12_PBE_IMPORT_PARAMS.new
    assert_equal [], s.certAttr
    s1 = CK_ATTRIBUTE.new ProtectServer::CKA_EXPORT, true
    s2 = CK_ATTRIBUTE.new ProtectServer::CKA_EXPORTABLE, false
    s.certAttr = [s1, s2]
    assert_equal [s1.to_hash, s2.to_hash], s.certAttr.map{|e| e.to_hash }
    GC.start
    assert_raises(ArgumentError){ s.certAttr = [s1, s2, nil] }
    assert_equal [s1.to_hash, s2.to_hash], s.certAttr.map{|e| e.to_hash }

    s.certAttr = []
    assert_equal [], s.certAttr
  end

  def test_constants
    assert_equal 0x80000990, ProtectServer::CKM_OS_UPGRADE, "CKM_OS_UPGRADE should be defined"
    assert_equal 0x80000128, ProtectServer::CKA_EXPORT, "CKA_EXPORT should be defined"
    assert_equal 0x80000129, ProtectServer::CKA_EXPORTABLE, "CKA_EXPORTABLE should be defined"
    assert ProtectServer::CKR_ET_NOT_ODD_PARITY.ancestors.include?(PKCS11::Error), "CKR_ET_NOT_ODD_PARITY should be defined"
    assert_equal 0x8000020c, ProtectServer::CKO_FM, "CKO_FM should be defined"
  end

  def test_loading
    pk = PKCS11::ProtectServer::Library.new(:sw, flags: 0)
    so_path = pk.so_path
    pk.close
    assert !so_path.empty?, "Used path shouldn't be empty"

    pk = PKCS11::ProtectServer::Library.new(so_path, flags: 0)
    pk.close
  end

  def test_loading2
    pk = PKCS11::ProtectServer::Library.new
    pk.load_library(:sw)
    pk.C_GetFunctionList
    pk.C_Initialize(flags: 0)
    pk.info
    pk.close
  end
end
