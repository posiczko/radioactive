# frozen_string_literal: true

require "net/http"
require "openssl"
require "resolv"
require "stringio"
require "tempfile"
require "uri"
require "zlib"

module Radioactive
  class Fetcher
    REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze
    RESERVED_HEADERS = %w[host user-agent accept-encoding].freeze
    CHUNK_SIZE = 16 * 1024
    DEFAULT_USER_AGENT = "Radioactive/#{Radioactive::VERSION}"

    # Single-label hosts that are entirely digits or 0x-prefix hex are not
    # valid RFC 1123 hostnames; they're SSRF-bypass attempts that some libc
    # getaddrinfo implementations historically resolved as IPs.
    NUMERIC_ONLY_HOST = /\A(\d+|0x[\da-f]+)\z/i

    # CRLF and NUL are illegal in HTTP header names and values (RFC 9110);
    # caller-supplied input containing these is a header-injection attempt.
    HEADER_INVALID_CHAR = /[\r\n\0]/

    DEFAULTS = {
      schemes: %w[http https].freeze,
      max_size: 2_097_152,
      open_timeout: 5,
      read_timeout: 10,
      total_timeout: 30,
      max_redirects: 3,
      accept_encoding: "identity",
      user_agent: DEFAULT_USER_AGENT,
      private_ranges: AddressCheck::DEFAULT_PRIVATE_RANGES,
      allow_private: false,
      allow_credentials: false,
      headers: {}.freeze
    }.freeze

    def initialize(**opts)
      validate_opts!(opts)
      @opts = DEFAULTS.merge(opts)
      @resolver = opts[:resolver] || Resolv
      @clock = opts[:clock] || MonotonicClock
    end

    def fetch(url, **call_opts)
      body = String.new(capacity: CHUNK_SIZE)
      meta = run_streaming(url, call_opts) { |chunk| body << chunk }
      Result.new(
        url: meta[:url],
        final_url: meta[:final_url],
        status: meta[:status],
        headers: meta[:headers],
        body: body,
        hops: meta[:hops]
      )
    end

    # No-block form returns a StringIO of the fully-buffered body (size-capped at
    # max_size; matches `URI.open` semantics). Block form streams chunks straight
    # to a Tempfile and yields it rewound, so peak memory per fetch is ~CHUNK_SIZE
    # rather than max_size — useful for high-concurrency or low-RAM callers.
    def open(url, **call_opts)
      return StringIO.new(fetch(url, **call_opts).body) unless block_given?

      io = Tempfile.new("radioactive")
      io.binmode
      begin
        run_streaming(url, call_opts) { |chunk| io.write(chunk) }
        io.rewind
        yield io
      ensure
        io.close
        io.unlink
      end
    end

    private

    def validate_opts!(opts)
      if opts.key?(:max_redirects) && opts[:max_redirects].negative?
        raise ArgumentError, "max_redirects must be >= 0"
      end
      if opts.key?(:max_size) && opts[:max_size] <= 0
        raise ArgumentError, "max_size must be > 0"
      end
    end

    # Runs the full fetch pipeline (parse, DNS pin, request, redirect-with-revalidation).
    # Yields each chunk of the *final* response body to the given block as it is read,
    # without intermediate buffering. Returns metadata only (no body).
    def run_streaming(url, call_opts, &chunk_block)
      validate_opts!(call_opts)
      opts = call_opts.empty? ? @opts : @opts.merge(call_opts)
      resolver = call_opts[:resolver] || @resolver
      clock = call_opts[:clock] || @clock

      start_uri = parse_url(url, opts)

      total_timeout = opts[:total_timeout]
      deadline = total_timeout ? clock.now + total_timeout : nil

      hops = []
      current = start_uri
      redirects_left = opts[:max_redirects]

      loop do
        check_deadline(deadline, clock)

        ip = pin_address(current, resolver, opts)
        kind, status, headers, body = perform_request(current, ip, opts, deadline, clock, &chunk_block)

        case kind
        when :redirect
          raise RedirectError, "redirect budget exhausted" if redirects_left <= 0

          redirects_left -= 1
          hops << current
          current = resolve_redirect(current, headers["location"], opts)
        when :final
          unless (200..299).cover?(status)
            raise ResponseError.new(
              "non-success status: #{status}",
              status: status, headers: headers, body: body
            )
          end

          return {
            url: start_uri,
            final_url: current,
            status: status,
            headers: headers,
            hops: hops.freeze
          }
        end
      end
    end

    def parse_url(url, opts)
      uri = url.is_a?(URI) ? url.dup : URI.parse(url.to_s)
      raise SchemeError, "URL has no host" if uri.host.nil? || uri.host.empty?
      unless opts[:schemes].include?(uri.scheme)
        raise SchemeError, "scheme not allowed: #{uri.scheme.inspect}"
      end
      if (uri.userinfo || uri.user) && !opts[:allow_credentials]
        raise SchemeError, "embedded credentials not allowed"
      end

      uri.host = canonicalize_host(uri.host)
      uri.fragment = nil
      uri
    rescue URI::InvalidURIError => e
      raise SchemeError, "invalid URL: #{e.message}"
    end

    # Defense-in-depth: canonicalize IP-literal hosts so the safety property
    # (we connect to the resolver-returned IP, not the user's input string)
    # doesn't depend on IPAddr.new being strict about leading zeros, octal,
    # decimal, or hex forms. Single-label numeric/hex hosts cannot be valid
    # hostnames and are rejected outright as ambiguous.
    def canonicalize_host(host)
      ip = IPAddr.new(host)
      ip.to_s
    rescue IPAddr::Error
      raise SchemeError, "ambiguous numeric host: #{host.inspect}" if NUMERIC_ONLY_HOST.match?(host)

      host
    end

    def pin_address(uri, resolver, opts)
      host = uri.host or raise AddressError, "URL has no host"
      addresses = AddressCheck.resolve(host, resolver)
      raise AddressError, "no addresses for #{host}" if addresses.empty?

      unless opts[:allow_private]
        addresses.each do |ip|
          if AddressCheck.forbidden?(ip, opts[:private_ranges])
            raise AddressError, "address in forbidden range: #{ip}"
          end
        end
      end

      addresses.first
    end

    def resolve_redirect(current, location, opts)
      target = URI.join(current.to_s, location)
      parse_url(target, opts)
    rescue URI::InvalidURIError => e
      raise SchemeError, "invalid redirect target: #{e.message}"
    end

    def check_deadline(deadline, clock)
      return unless deadline

      remaining = deadline - clock.now
      raise TimeoutError, "total_timeout exceeded" if remaining <= 0
    end

    def clamp_timeout(value, deadline, clock)
      return value unless deadline && value

      remaining = deadline - clock.now
      raise TimeoutError, "total_timeout exceeded" if remaining <= 0

      [value, remaining].min
    end

    def perform_request(uri, ip, opts, deadline, clock, &chunk_block)
      http = build_http(uri, ip, opts, deadline, clock)
      req = build_request(uri, opts)

      result = nil
      begin
        http.start do |conn|
          conn.request(req) do |res|
            code = res.code.to_i
            headers = headers_hash(res)

            if REDIRECT_STATUSES.include?(code) && headers["location"]
              result = [:redirect, code, headers, nil]
            elsif (200..299).cover?(code)
              # 2xx: stream chunks straight to caller; no buffering here.
              read_body!(res, headers, opts, deadline, clock, &chunk_block)
              result = [:final, code, headers, nil]
            else
              # Non-2xx: buffer body so ResponseError can carry partial data.
              error_body = String.new(capacity: CHUNK_SIZE)
              read_body!(res, headers, opts, deadline, clock) { |chunk| error_body << chunk }
              result = [:final, code, headers, error_body]
            end
          end
        end
      rescue Net::OpenTimeout, Net::ReadTimeout => e
        raise TimeoutError, e.message
      rescue OpenSSL::SSL::SSLError, SocketError, Errno::ECONNREFUSED,
        Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNRESET,
        IOError => e
        raise ResponseError, "transport error: #{e.class}: #{e.message}"
      end

      result || raise(ResponseError, "request produced no response")
    end

    def build_http(uri, ip, opts, deadline, clock)
      host = uri.host or raise SchemeError, "URL has no host"
      port = uri.port || ((uri.scheme == "https") ? 443 : 80)
      http = Net::HTTP.new(host, port)
      http.ipaddr = ip.to_s
      http.use_ssl = (uri.scheme == "https")
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER if http.use_ssl?

      if (open_t = clamp_timeout(opts[:open_timeout], deadline, clock))
        http.open_timeout = open_t
      end
      if (read_t = clamp_timeout(opts[:read_timeout], deadline, clock))
        http.read_timeout = read_t
      end
      if http.respond_to?(:write_timeout=) && (write_t = clamp_timeout(opts[:open_timeout], deadline, clock))
        http.write_timeout = write_t
      end
      http
    end

    def build_request(uri, opts)
      path = uri.path.to_s
      path = "/" if path.empty?
      path = "#{path}?#{uri.query}" if uri.query
      req = Net::HTTP::Get.new(path)
      req["User-Agent"] = opts[:user_agent]
      req["Accept-Encoding"] = opts[:accept_encoding]
      (opts[:headers] || {}).each do |k, v|
        name = k.to_s
        value = v.to_s
        next if RESERVED_HEADERS.include?(name.downcase)
        if HEADER_INVALID_CHAR.match?(name) || HEADER_INVALID_CHAR.match?(value)
          raise SchemeError, "header contains CR/LF/NUL: #{name.inspect}"
        end

        req[name] = value
      end
      req
    end

    def headers_hash(res)
      res.each_header.to_h { |k, v| [k.downcase, v] }
    end

    # Reads the response body, decoding if needed, yielding each chunk to the
    # given block. Enforces max_size on the *post-decoding* size so opt-in gzip
    # is bounded by decoded bytes.
    def read_body!(res, headers, opts, deadline, clock, &chunk_block)
      max = opts[:max_size]
      cl = res.content_length
      raise SizeError, "Content-Length #{cl} exceeds max_size #{max}" if cl && cl > max

      ce = headers["content-encoding"].to_s.downcase
      accept = opts[:accept_encoding].to_s.downcase

      if ce.empty? || ce == "identity"
        read_plain!(res, max, deadline, clock, &chunk_block)
      elsif accept == "identity"
        raise EncodingError, "unexpected Content-Encoding: #{ce} (accept_encoding=identity)"
      elsif accept.include?("gzip") && (ce == "gzip" || ce == "x-gzip")
        read_gzip!(res, max, deadline, clock, &chunk_block)
      else
        raise EncodingError, "unsupported Content-Encoding: #{ce}"
      end
    end

    def read_plain!(res, max, deadline, clock)
      total = 0
      res.read_body do |chunk|
        check_deadline(deadline, clock)
        total += chunk.bytesize
        raise SizeError, "body exceeded max_size #{max}" if total > max

        yield chunk
      end
    end

    def read_gzip!(res, max, deadline, clock)
      inflater = Zlib::Inflate.new(Zlib::MAX_WBITS + 16)
      total = 0
      begin
        res.read_body do |chunk|
          check_deadline(deadline, clock)
          decoded = inflater.inflate(chunk)
          total += decoded.bytesize
          raise SizeError, "body exceeded max_size #{max}" if total > max

          yield decoded unless decoded.empty?
        end
        tail = inflater.finish
        unless tail.empty?
          total += tail.bytesize
          raise SizeError, "body exceeded max_size #{max}" if total > max

          yield tail
        end
      rescue Zlib::Error => e
        raise EncodingError, "gzip decode failed: #{e.message}"
      ensure
        begin
          inflater.close
        rescue
          # already closed
        end
      end
    end
  end
end
