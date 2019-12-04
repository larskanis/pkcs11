require "minitest/autorun"
require "pkcs11"
require "test/helper"

class TestPkcs11Slot < Minitest::Test
  include PKCS11

  attr_reader :slots
  attr_reader :slot

  def setup
    $pkcs11 ||= open_softokn
    @slots = pk.active_slots
    @slot = slots.last
  end

  def teardown
  end

  def pk
    $pkcs11
  end

  def test_info
    sinfo = slot.info

    assert sinfo.inspect =~ /manufacturerID=/, 'Slot info should tell about manufacturerID'

    assert_kind_of Integer, sinfo.flags
    assert sinfo.manufacturerID =~ /Mozilla/i, "It's the mozilla libaray we test against"
    assert sinfo.slotDescription =~ /Private Key/i, "It's the slot with users private keys"
    assert_kind_of Integer, sinfo.hardwareVersion.major, "Version should be a number"
    assert_kind_of Integer, sinfo.hardwareVersion.minor, "Version should be a number"
    assert_kind_of Integer, sinfo.firmwareVersion.major, "Version should be a number"
    assert_kind_of Integer, sinfo.firmwareVersion.minor, "Version should be a number"
  end

  def test_token_info
    ti = slot.token_info
    assert ti.inspect =~ /serialNumber=/, 'Token info should contain a serialNumber'
  end

  def test_mechanisms
    assert_equal false, slot.mechanisms.empty?, 'There should be some mechanisms'
    slot.mechanisms.each do |m|
      info = slot.mechanism_info(m)
      assert_kind_of CK_MECHANISM_INFO, info, 'Mechanism info should get a CK_MECHANISM_INFO'
      assert info.inspect =~ /ulMaxKeySize=/, 'Mechanism info should tell about max key size'
    end
  end

  def test_mechanism_info
    info1 = slot.mechanism_info(:DES3_CBC)
    assert_kind_of CK_MECHANISM_INFO, info1, 'Mechanism info should get a CK_MECHANISM_INFO'
    assert info1.inspect =~ /ulMinKeySize=/, 'Mechanism info should tell about min key size'

    info2 = slot.mechanism_info(CKM_DES3_CBC)
    assert_equal info1.to_hash, info2.to_hash, 'Mechanism infos should be equal'
  end

  def test_session
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    session = slot.open(flags){|_session|
      assert _session.info.inspect =~ /state=/, 'Session info should tell about it\'s state'
    }

    session = slot.open(flags)
    assert session.info.inspect =~ /flags=/, 'Session info should tell about it\'s flags'
    session.close
  end

  def test_session2
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    _session = slot.open(flags)
    slot.close_all_sessions
  end
end

