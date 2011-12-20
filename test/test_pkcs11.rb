require "test/unit"
require "pkcs11"
require "test/helper"

class TestPkcs11 < Test::Unit::TestCase
  attr_reader :pk

  def open
    @pk = open_softokn
  end

  def close
    @pk.close
    @pk = nil
    GC.start
  end

  def test_info
    open
    info = pk.info
    assert info.inspect =~ /cryptokiVersion=/, 'There should be a version in the library info'
    close
  end

  def test_slots
    open
    slots = pk.active_slots
    assert slots.length>=1, 'Hope there is at least one active slot'
    close
  end

  def test_close
    open
    pk.close
    pk.unload_library
    assert_raise(PKCS11::Error){ pk.info }

    @pk = PKCS11.open
    pk.load_library(find_softokn)

    pk.C_GetFunctionList

    pargs = PKCS11::CK_C_INITIALIZE_ARGS.new
    pargs.flags = 0
    pargs.pReserved = softokn_params.join(" ")
    pk.C_Initialize(pargs)

    pk.info
    close
  end

  def test_C_Initialize_with_Hash
    pk = PKCS11.open
    pk.load_library(find_softokn)
    pk.C_GetFunctionList
    pk.C_Initialize(:flags=>0, :pReserved=>softokn_params_string)
    pk.info
    pk.close
  end
end
