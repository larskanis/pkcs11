require "minitest/autorun"
require "pkcs11_luna"
require "test/luna_helper"

class TestPkcs11Luna < Minitest::Test
  include PKCS11
  
  RUBY = File.join(RbConfig::CONFIG['bindir'], RbConfig::CONFIG['ruby_install_name'])
  FILE = File.dirname(__FILE__)
  
  @slot = LunaHelper.get_slot_password()
  
  def get_password
    STDIN.echo = false
    while ((c = STDIN.getch) != '\n')
      print c
    end
    STDIN.echo = true
  end
  
  def setup
    @pk = Luna::Library.new
    @slot, @password = LunaHelper.get_slot_password()
  end
  
  def teardown
    @pk.close
  end

=begin 
  def test_slots_are_luna
    pkcs11 = @pk
    pkcs11.slots.each do |slot|
      assert_equal(slot.class.to_s, "PKCS11::Luna::Slot")
    end
  end


  MAJOR = 10
  MINOR = 10
  def test_application_id 
    pkcs11 = @pk
    pkcs11.set_application_id(MAJOR, MINOR)
    slot = Luna::Slot.new(pkcs11, @slot)
    begin
      slot.open_application_id(MAJOR, MINOR)
    rescue CKR_DATA_INVALID
      slot.close_application_id(MAJOR, MINOR)
    end
    session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
    session.login(:USER, @password)
    file = File.join(FILE, 'app_id_helper.rb')
    cmd = "#{RUBY} #{file} #{@slot}"  
    IO.popen(cmd, 'r') do |p|
       p.read
    end
    assert $?.success?, "The subprocess did not return successfully."
    
    
    session.logout
    session.close
    slot.close_application_id(MAJOR, MINOR)
  end
=end
  
  def test_mechanisms_list
    pkcs11 = @pk
    slot = Slot.new(pkcs11, @slot)
    mechanisms = slot.mechanisms
    mechanisms.each do |mech_id|
      assert(Luna::MECHANISMS.key?(mech_id))
    end
  end
  
  def test_init_token
    pkcs11 = @pk
    slot = Slot.new(pkcs11, @slot)
    
    assert_raises(Luna::CKR_OPERATION_NOT_ALLOWED, CKR_USER_TYPE_INVALID) {
      slot.init_token("anypin", "new_label")
    }   
  end
  
  def test_init_pin
    pkcs11 = @pk
    slot = Slot.new(pkcs11, @slot)
    session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
    session.login(:USER, @password)
    assert_raises(Luna::CKR_OPERATION_NOT_ALLOWED, CKR_FUNCTION_NOT_SUPPORTED) {
      session.init_pin("anypin")
    }
    session.logout
    session.close
  end
  
  def test_set_pin
    pkcs11 = @pk
    slot = Slot.new(pkcs11, @slot)
    session = slot.open(CKF_RW_SESSION | CKF_SERIAL_SESSION)
    session.login(:USER, @password)
    session.set_pin(@password, @password)
    session.logout
    session.close
  end
  
  def test_wait_for_slot_event
    assert_raises(Luna::CKR_OPERATION_NOT_ALLOWED, CKR_FUNCTION_NOT_SUPPORTED) {
      @pk.wait_for_slot_event
    }
  end
  
end
