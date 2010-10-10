require "test/unit"
require "pkcs11"
require "test/helper"
require "openssl"

class TestPkcs11Thread < Test::Unit::TestCase
  include PKCS11

  attr_reader :slots
  attr_reader :slot
  attr_reader :session

  def setup
    $pkcs11 ||= open_softokn
    @slots = $pkcs11.active_slots
    @slot = slots.last
    @session = slot.open
    session.login(:USER, "")
  end

  def teardown
    @session.logout
    @session.close
  end

  def test_concurrency
    return unless self.respond_to?(:skip)
    skip "PKCS#11 calls will block on Ruby 1.8.x" if RUBY_VERSION<'1.9'

    count = 0
    th = Thread.new{
      loop do
        count += 1
        sleep 0.01
      end
    }
    # This should take some seconds:
    pub_key, priv_key = session.generate_key_pair(:RSA_PKCS_KEY_PAIR_GEN,
      {:MODULUS_BITS=>1408, :PUBLIC_EXPONENT=>[3].pack("N"), :TOKEN=>false},
      {})
    th.kill
    assert_operator count, :>, 10, "The second thread should count further concurrent to the key generation"
  end

end
