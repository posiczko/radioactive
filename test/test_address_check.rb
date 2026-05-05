# frozen_string_literal: true

require "test_helper"
require "ipaddr"

class TestAddressCheck < Minitest::Test
  def forbidden?(ip)
    Radioactive::AddressCheck.forbidden?(IPAddr.new(ip))
  end

  def test_loopback_v4_blocked
    assert forbidden?("127.0.0.1")
    assert forbidden?("127.255.255.254")
  end

  def test_loopback_v6_blocked
    assert forbidden?("::1")
  end

  def test_rfc1918_blocked
    assert forbidden?("10.0.0.1")
    assert forbidden?("172.16.0.1")
    assert forbidden?("172.31.255.254")
    assert forbidden?("192.168.1.1")
  end

  def test_link_local_and_metadata_blocked
    assert forbidden?("169.254.0.1")
    assert forbidden?("169.254.169.254") # AWS/GCP metadata
  end

  def test_cgnat_blocked
    assert forbidden?("100.64.0.1")
  end

  def test_unspecified_blocked
    assert forbidden?("0.0.0.0")
    assert forbidden?("::")
  end

  def test_documentation_ranges_blocked
    assert forbidden?("192.0.2.1")
    assert forbidden?("198.51.100.1")
    assert forbidden?("203.0.113.1")
  end

  def test_multicast_blocked
    assert forbidden?("224.0.0.1")
    assert forbidden?("ff00::1")
  end

  def test_ipv6_ula_and_link_local_blocked
    assert forbidden?("fc00::1")
    assert forbidden?("fd12:3456::1")
    assert forbidden?("fe80::1")
  end

  def test_ipv4_mapped_v6_folds_to_v4_check
    assert forbidden?("::ffff:127.0.0.1")
    assert forbidden?("::ffff:10.0.0.1")
    refute forbidden?("::ffff:8.8.8.8")
  end

  def test_public_addresses_pass
    refute forbidden?("8.8.8.8")
    refute forbidden?("1.1.1.1")
    refute forbidden?("2606:4700:4700::1111")
  end

  def test_resolve_with_ip_literal_short_circuits_resolver
    boom_resolver = Class.new {
      def getaddresses(_)
        raise "resolver should not be called"
      end
    }.new
    addrs = Radioactive::AddressCheck.resolve("8.8.8.8", boom_resolver)
    assert_equal [IPAddr.new("8.8.8.8")], addrs
  end

  def test_resolve_uses_resolver_for_hostnames
    resolver = Class.new {
      def getaddresses(host)
        (host == "example.com") ? ["93.184.216.34", "2606:2800:220:1::248:1893"] : []
      end
    }.new
    addrs = Radioactive::AddressCheck.resolve("example.com", resolver)
    assert_equal 2, addrs.size
    assert_equal IPAddr.new("93.184.216.34"), addrs.first
  end
end
