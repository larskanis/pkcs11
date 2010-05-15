require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11 < Test::Unit::TestCase
  def setup
    @pk = open_softokn
  end

  def teardown
    @pk.close
    @pk = nil
    GC.start
  end

  def pk
    @pk
  end
  
  def test_info
    info = pk.info
    assert info.inspect =~ /cryptokiVersion=/, 'There should be a version in the library info'
  end

  def test_slots
    slots = pk.active_slots
    assert slots.length>=1, 'Hope there is at least one active slot'
  end

  def test_close
    pk.close
    assert_raise(PKCS11::Error){ pk.info }
    pk.close
    assert_raise(PKCS11::Error){ pk.active_slots }
  end
end
