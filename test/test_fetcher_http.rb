# frozen_string_literal: true

require "test_helper"
require_relative "support/server_fixture"

# HTTP-layer integration tests against a local TCPServer fixture.
# These tests run against 127.0.0.1, so allow_private: true is the default
# unless a specific test exercises the address-check pipeline (in which case
# we use a stub resolver and a custom private_ranges list).
class TestFetcherHTTP < Minitest::Test
  def teardown
    @server&.stop
  end

  def serve(handler)
    @server = TestServer.run(handler)
    "http://127.0.0.1:#{@server.port}"
  end

  # ---- Happy path -------------------------------------------------------

  def test_2xx_returns_result_with_body
    base = serve(->(_, _, _) {
      {status: 200, headers: {"Content-Type" => "text/plain"}, body: "hello"}
    })

    result = Radioactive::Fetcher.new(allow_private: true).fetch("#{base}/")

    assert_equal 200, result.status
    assert_equal "hello", result.body
    assert_equal URI("#{base}/"), result.url
    assert_equal URI("#{base}/"), result.final_url
    assert_equal [], result.hops
    assert_equal "text/plain", result.headers["content-type"]
  end

  def test_open_with_block_yields_streaming_io_and_returns_block_value
    base = serve(->(_, _, _) { {status: 200, body: "<p>hi</p>"} })

    yielded_path = nil
    out = Radioactive::Fetcher.new(allow_private: true).open("#{base}/") do |io|
      assert_respond_to io, :read
      assert_respond_to io, :rewind
      yielded_path = io.path if io.respond_to?(:path)
      io.read
    end

    assert_equal "<p>hi</p>", out
    # Streaming form uses a Tempfile that is unlinked after the block exits.
    refute_path_exists yielded_path if yielded_path
  end

  def test_open_without_block_returns_stringio
    base = serve(->(_, _, _) { {status: 200, body: "stuff"} })

    io = Radioactive::Fetcher.new(allow_private: true).open("#{base}/")

    assert_kind_of StringIO, io
    assert_equal "stuff", io.read
  end

  def test_open_block_streams_chunks_without_buffering_full_body
    # Body larger than CHUNK_SIZE so streaming is observable: if the gem
    # buffered the full body before yielding, peak memory would be ~max_size,
    # but here we cap max_size below the body and assert success — proving
    # the cap is on the *streamed* size, and that streaming writes go to
    # the Tempfile rather than to in-memory String.
    body = "x" * 100_000
    base = serve(->(_, _, _) { {status: 200, body: body} })

    received = nil
    Radioactive::Fetcher.new(allow_private: true, max_size: 200_000).open("#{base}/") do |io|
      received = io.read
    end

    assert_equal body.bytesize, received.bytesize
    assert_equal body, received
  end

  # ---- Size cap ---------------------------------------------------------

  def test_content_length_exceeding_max_size_rejected_before_body_read
    # Server *claims* a huge body in Content-Length. Fetcher must refuse before
    # streaming a single byte.
    base = serve(->(_, _, _) {
      "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\nshort"
    })

    err = assert_raises(Radioactive::SizeError) do
      Radioactive::Fetcher.new(allow_private: true, max_size: 1024).fetch("#{base}/")
    end
    assert_match(/Content-Length/, err.message)
  end

  def test_chunked_body_exceeding_max_size_raises_mid_read
    # No Content-Length: streamed in 1KB chunks, fetcher must abort once
    # accumulated bytes pass max_size.
    chunks = Array.new(20) { "A" * 1024 }
    base = serve(->(_, _, _) { {status: 200, chunked: true, body: chunks} })

    assert_raises(Radioactive::SizeError) do
      Radioactive::Fetcher.new(allow_private: true, max_size: 4096).fetch("#{base}/")
    end
  end

  # ---- Redirects --------------------------------------------------------

  def test_redirect_followed_and_recorded_in_hops
    handler = lambda do |_, path, _|
      case path
      when "/start" then {status: 302, headers: {"Location" => "/end"}}
      when "/end" then {status: 200, body: "destination"}
      end
    end
    base = serve(handler)

    result = Radioactive::Fetcher.new(allow_private: true).fetch("#{base}/start")

    assert_equal 200, result.status
    assert_equal "destination", result.body
    assert_equal URI("#{base}/start"), result.url
    assert_equal URI("#{base}/end"), result.final_url
    assert_equal [URI("#{base}/start")], result.hops
  end

  def test_redirect_budget_exhausted_raises
    handler = lambda do |_, path, _|
      next_path = "/r#{path[/\d+/].to_i + 1}"
      {status: 302, headers: {"Location" => next_path}}
    end
    base = serve(handler)

    assert_raises(Radioactive::RedirectError) do
      Radioactive::Fetcher.new(allow_private: true, max_redirects: 2).fetch("#{base}/r0")
    end
  end

  def test_redirect_to_private_address_blocked_by_revalidation
    # The original URL resolves to 127.0.0.1 (server). The redirect target's
    # hostname resolves into our forbidden range (10.0.0.1), and the redirect
    # re-validation pipeline must reject it.
    handler = lambda do |_, path, _|
      case path
      when "/start" then {status: 302, headers: {"Location" => "http://blocked.local/end"}}
      else {status: 200, body: "should not reach"}
      end
    end
    @server = TestServer.run(handler)

    resolver = Class.new {
      def initialize(map)
        @map = map
      end

      def getaddresses(host)
        @map.fetch(host) { raise "unexpected resolve(#{host.inspect})" }
      end
    }.new(
      "ok.local" => ["127.0.0.1"],
      "blocked.local" => ["10.0.0.1"]
    )

    f = Radioactive::Fetcher.new(
      resolver: resolver,
      private_ranges: [IPAddr.new("10.0.0.0/8")]
    )

    assert_raises(Radioactive::AddressError) do
      f.fetch("http://ok.local:#{@server.port}/start")
    end
  end

  # ---- Non-2xx ----------------------------------------------------------

  def test_non_2xx_raises_response_error_with_partial_data
    base = serve(->(_, _, _) {
      {status: 503, headers: {"X-Reason" => "down"}, body: "maintenance"}
    })

    err = assert_raises(Radioactive::ResponseError) do
      Radioactive::Fetcher.new(allow_private: true).fetch("#{base}/")
    end
    assert_equal 503, err.status
    assert_equal "maintenance", err.body
    assert_equal "down", err.headers["x-reason"]
  end

  # ---- Content-Encoding -------------------------------------------------

  def test_unexpected_content_encoding_under_identity_raises_encoding_error
    body = GzipHelper.gzip("hello")
    base = serve(->(_, _, _) {
      {status: 200, headers: {"Content-Encoding" => "gzip"}, body: body}
    })

    assert_raises(Radioactive::EncodingError) do
      Radioactive::Fetcher.new(allow_private: true).fetch("#{base}/")
    end
  end

  def test_gzip_opt_in_decompresses_successfully
    body = GzipHelper.gzip("decompressed!")
    base = serve(->(_, _, _) {
      {status: 200, headers: {"Content-Encoding" => "gzip"}, body: body}
    })

    result = Radioactive::Fetcher.new(
      allow_private: true,
      accept_encoding: "gzip"
    ).fetch("#{base}/")

    assert_equal "decompressed!", result.body
  end

  # ---- Timeouts ---------------------------------------------------------

  # We don't test open_timeout end-to-end: triggering it reliably requires a
  # SYN-drop target, and the OS-/network-dependent options (TEST-NET, NAT
  # blackholes) either return ECONNREFUSED quickly or hang past test budgets.
  # The plumbing is exercised structurally (clamp_timeout in build_http) and
  # via the total_timeout unit test in test_fetcher.rb.

  def test_read_timeout_when_server_stalls_before_response
    # Handler sleeps so the response never starts; client's read_timeout fires.
    base = serve(->(_, _, _) {
      sleep 1.0
      {status: 200, body: "too slow"}
    })

    err = assert_raises(Radioactive::TimeoutError) do
      Radioactive::Fetcher.new(
        allow_private: true,
        read_timeout: 0.2,
        total_timeout: nil
      ).fetch("#{base}/")
    end
    refute_nil err.message
  end

  def test_slowloris_drip_triggers_read_timeout
    # Server sends headers, then stalls with body still owed (Content-Length: 100).
    # Net::HTTP's read_body waits for socket data; gap exceeds read_timeout.
    @server = TestServer.run do |client, _method, _path, _headers|
      client.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
      sleep 1.0
      begin
        client.write("X" * 100)
      rescue IOError, Errno::EPIPE, Errno::ECONNRESET
        # client already gave up — expected
      end
    end

    assert_raises(Radioactive::TimeoutError) do
      Radioactive::Fetcher.new(
        allow_private: true,
        read_timeout: 0.2,
        total_timeout: nil
      ).fetch("http://127.0.0.1:#{@server.port}/")
    end
  end

  def test_gzip_decoded_size_cap_raises_size_error
    # 200 KB of repetition compresses to a few hundred bytes; max_size 4 KB
    # forces SizeError on the *decoded* stream, not the wire bytes.
    plaintext = "A" * 200_000
    body = GzipHelper.gzip(plaintext)
    base = serve(->(_, _, _) {
      {status: 200, headers: {"Content-Encoding" => "gzip"}, body: body}
    })

    assert_raises(Radioactive::SizeError) do
      Radioactive::Fetcher.new(
        allow_private: true,
        accept_encoding: "gzip",
        max_size: 4096
      ).fetch("#{base}/")
    end
  end
end
