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
    assert 'There should be a version in the library info', info.inspect =~ /cryptokiVersion=/
  end

  def test_slots
    slots = pk.active_slots
    assert 'Hope there is at least one active slot', slots.length>=1
  end
end
