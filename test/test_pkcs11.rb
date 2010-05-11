require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11 < Test::Unit::TestCase
  def setup
    $pkcs11 ||= open_softokn
  end

  def teardown
#    $pkcs11 = nil
    GC.start
  end

  def pk
    $pkcs11
  end
  
  def test_info
    info = pk.info
    assert info.inspect =~ /cryptokiVersion=/, 'There should be a version in the library info'
  end

  def test_slots
    slots = pk.active_slots
    assert slots.length>=1, 'Hope there is at least one active slot'
  end
end
