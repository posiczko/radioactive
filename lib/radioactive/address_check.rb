# frozen_string_literal: true

require "ipaddr"

module Radioactive
  module AddressCheck
    DEFAULT_PRIVATE_RANGES = %w[
      0.0.0.0/8
      10.0.0.0/8
      100.64.0.0/10
      127.0.0.0/8
      169.254.0.0/16
      172.16.0.0/12
      192.0.0.0/24
      192.0.2.0/24
      192.168.0.0/16
      198.18.0.0/15
      198.51.100.0/24
      203.0.113.0/24
      224.0.0.0/4
      240.0.0.0/4
      255.255.255.255/32
      ::/128
      ::1/128
      64:ff9b::/96
      100::/64
      2001::/32
      2001:db8::/32
      fc00::/7
      fe80::/10
      ff00::/8
    ].map { |cidr| IPAddr.new(cidr) }.freeze

    module_function

    # @param ip [IPAddr]
    # @param ranges [Array<IPAddr>]
    def forbidden?(ip, ranges = DEFAULT_PRIVATE_RANGES)
      candidate = ip.ipv4_mapped? ? ip.native : ip
      ranges.any? { |r| r.include?(candidate) }
    end

    # @param host [String]
    # @param resolver [#getaddresses]
    # @return [Array<IPAddr>]
    def resolve(host, resolver)
      begin
        ip = IPAddr.new(host)
        return [ip]
      rescue IPAddr::Error
      end

      addresses = Array(resolver.getaddresses(host))
      addresses.map { |a| IPAddr.new(a) }
    rescue IPAddr::Error => e
      raise AddressError, "could not parse resolved address: #{e.message}"
    end
  end
end
