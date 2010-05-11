require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11Slot < Test::Unit::TestCase
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
    
    [
      sinfo.slotDescription, sinfo.manufacturerID, sinfo.flags,
      sinfo.hardwareVersion, sinfo.firmwareVersion
    ]
  end

  def test_token_info
    ti = slot.token_info
    assert ti.inspect =~ /serialNumber=/, 'Token info should contain a serialNumber'
  end
  
  def test_mechanisms
    assert_equal false, slot.mechanisms.empty?, 'There should be some mechanisms'
    slot.mechanisms.each do |m|
      info = slot.mechanism_info(m)
      assert_equal CK_MECHANISM_INFO, info.class, 'Mechanism info should a CK_MECHANISM_INFO'
      assert info.inspect =~ /ulMaxKeySize=/, 'Mechanism info should tell about max key size'
    end
  end

  def test_session
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    session = slot.open(flags){|session|
      assert session.info.inspect =~ /state=/, 'Session info should tell about it\'s state'
    }
    
    session = slot.open(flags)
    assert session.info.inspect =~ /flags=/, 'Session info should tell about it\'s flags'
    session.close
  end

  def test_session2
    flags = CKF_SERIAL_SESSION #| CKF_RW_SESSION
    session = slot.open(flags)
    slot.close_all_sessions
  end
end

