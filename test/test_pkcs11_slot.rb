require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11Slot < Test::Unit::TestCase
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
    
    assert 'Slot info should tell about manufacturerID', sinfo.inspect =~ /manufacturerID=/
    
    [
      sinfo.slotDescription, sinfo.manufacturerID, sinfo.flags,
      sinfo.hardwareVersion, sinfo.firmwareVersion
    ]
  end

  def test_token_info
    ti = slot.token_info
    assert 'Token info should contain a serialNumber', ti =~ /serialNumber=/
  end
  
  def test_mechanisms
    assert 'There should be some mechanisms', !slot.mechanisms.empty?
    slot.mechanisms.each do |m|
      assert 'Mechanism info should tell about max key size', slot.mechanism_info(m).inspect =~ /ulMaxKeySize=/
    end
  end

  def test_session
    flags = PKCS11::CKF_SERIAL_SESSION | PKCS11::CKF_RW_SESSION
    session = slot.open(flags){|session|
      assert 'Session info should tell about it\'s state', session.info =~ /state=/
    }
    
    session = slot.open(flags)
    assert 'Session info should tell about it\'s flags', session.info =~ /flags=/
    session.close
  end
end

