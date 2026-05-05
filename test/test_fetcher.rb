# frozen_string_literal: true

require "test_helper"

class TestFetcher < Minitest::Test
  # Resolver that returns a fixed mapping; raises if asked about an unknown host
  # so we never accidentally hit real DNS in tests.
  class StubResolver
    def initialize(map)
      @map = map
    end

    def getaddresses(host)
      @map.fetch(host) { raise "unexpected resolve(#{host.inspect})" }
    end
  end

  # Clock that returns successive values; raises if called more times than seeded
  # so a test that "works" by accident (extra calls) fails loudly.
  class StubClock
    def initialize(values)
      @values = values.dup
    end

    def now
      @values.shift || raise("clock exhausted")
    end
  end

  def fetcher(opts = {})
    Radioactive::Fetcher.new(
      resolver: StubResolver.new(opts.delete(:resolver_map) || {}),
      **opts
    )
  end

  # ---- URL parsing / scheme / credentials --------------------------------

  def test_disallowed_scheme_rejected
    assert_raises(Radioactive::SchemeError) { fetcher.fetch("file:///etc/passwd") }
    assert_raises(Radioactive::SchemeError) { fetcher.fetch("gopher://example.com/") }
    assert_raises(Radioactive::SchemeError) { fetcher.fetch("javascript:alert(1)") }
  end

  def test_missing_host_rejected
    assert_raises(Radioactive::SchemeError) { fetcher.fetch("http:///path") }
    assert_raises(Radioactive::SchemeError) { fetcher.fetch("not a url") }
  end

  def test_embedded_credentials_rejected_by_default
    f = fetcher(resolver_map: {"example.com" => ["93.184.216.34"]})
    assert_raises(Radioactive::SchemeError) do
      f.fetch("http://user:pass@example.com/")
    end
  end

  def test_custom_scheme_allowlist
    f = fetcher(schemes: %w[https], resolver_map: {"example.com" => ["93.184.216.34"]})
    assert_raises(Radioactive::SchemeError) { f.fetch("http://example.com/") }
  end

  # ---- DNS / address validation ------------------------------------------

  def test_empty_dns_resolution_raises_address_error
    f = fetcher(resolver_map: {"nope.example" => []})
    assert_raises(Radioactive::AddressError) { f.fetch("http://nope.example/") }
  end

  def test_resolver_returning_loopback_blocked
    f = fetcher(resolver_map: {"evil.example" => ["127.0.0.1"]})
    err = assert_raises(Radioactive::AddressError) { f.fetch("http://evil.example/") }
    assert_match(/forbidden/, err.message)
  end

  def test_resolver_returning_metadata_blocked
    f = fetcher(resolver_map: {"meta.example" => ["169.254.169.254"]})
    assert_raises(Radioactive::AddressError) { f.fetch("http://meta.example/") }
  end

  def test_resolver_returning_rfc1918_blocked
    f = fetcher(resolver_map: {"intranet.example" => ["10.0.0.5"]})
    assert_raises(Radioactive::AddressError) { f.fetch("http://intranet.example/") }
  end

  def test_dual_a_record_strict_rejection
    # One public, one private — strict mode rejects the whole resolution
    # to defeat DNS-rebinding-style SSRF.
    f = fetcher(resolver_map: {"mixed.example" => ["8.8.8.8", "10.0.0.1"]})
    assert_raises(Radioactive::AddressError) { f.fetch("http://mixed.example/") }
  end

  def test_url_with_ip_literal_to_private_blocked
    # No resolver entry needed; AddressCheck.resolve short-circuits IP literals.
    f = fetcher
    assert_raises(Radioactive::AddressError) { f.fetch("http://127.0.0.1/") }
  end

  # ---- total_timeout pre-check ------------------------------------------

  def test_total_timeout_exceeded_before_request
    # First clock.call sets the deadline; the second (in the loop's
    # check_deadline) is well past it, so we raise before any HTTP.
    f = Radioactive::Fetcher.new(
      total_timeout: 5,
      resolver: StubResolver.new("ok.example" => ["8.8.8.8"]),
      clock: StubClock.new([0.0, 100.0])
    )
    assert_raises(Radioactive::TimeoutError) { f.fetch("http://ok.example/") }
  end

  # ---- option validation -------------------------------------------------

  def test_negative_max_redirects_rejected
    assert_raises(ArgumentError) { Radioactive::Fetcher.new(max_redirects: -1) }
  end

  def test_zero_max_size_rejected
    assert_raises(ArgumentError) { Radioactive::Fetcher.new(max_size: 0) }
  end

  # ---- IP-literal canonicalization (defense-in-depth) -------------------

  def test_decimal_ip_literal_host_rejected
    # 2130706433 == 127.0.0.1 in libc inet_addr. Some OSes historically
    # honored this form; we reject it outright so the safety doesn't depend
    # on resolver behavior.
    err = assert_raises(Radioactive::SchemeError) { fetcher.fetch("http://2130706433/") }
    assert_match(/numeric host/, err.message)
  end

  def test_hex_ip_literal_host_rejected
    err = assert_raises(Radioactive::SchemeError) { fetcher.fetch("http://0x7f000001/") }
    assert_match(/numeric host/, err.message)
  end

  # ---- Header CRLF injection (defense-in-depth) -------------------------

  def test_caller_supplied_header_with_crlf_in_value_rejected
    # Even with allow_private: true (so DNS/address checks don't intervene),
    # the request must fail before any socket is opened.
    f = Radioactive::Fetcher.new(
      allow_private: true,
      resolver: StubResolver.new("ok.example" => ["127.0.0.1"]),
      headers: {"X-Tenant" => "alice\r\nX-Admin: true"}
    )
    err = assert_raises(Radioactive::SchemeError) { f.fetch("http://ok.example/") }
    assert_match(/CR\/LF/, err.message)
  end

  def test_caller_supplied_header_with_crlf_in_name_rejected
    f = Radioactive::Fetcher.new(
      allow_private: true,
      resolver: StubResolver.new("ok.example" => ["127.0.0.1"]),
      headers: {"X-Bad\r\nX-Inject" => "value"}
    )
    assert_raises(Radioactive::SchemeError) { f.fetch("http://ok.example/") }
  end

  def test_caller_supplied_header_with_nul_rejected
    f = Radioactive::Fetcher.new(
      allow_private: true,
      resolver: StubResolver.new("ok.example" => ["127.0.0.1"]),
      headers: {"X-Bad" => "alice\x00admin"}
    )
    assert_raises(Radioactive::SchemeError) { f.fetch("http://ok.example/") }
  end
end
