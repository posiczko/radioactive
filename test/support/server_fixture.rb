# frozen_string_literal: true

require "socket"
require "stringio"
require "zlib"

# Tiny single-host HTTP fixture used by HTTP-layer tests.
#
# Two modes:
#   1. TestServer.run(handler) — handler.call(method, path, headers) returns
#      a String (raw HTTP response) or a Hash (status:/headers:/body:/chunked:).
#   2. TestServer.run { |client, method, path, headers| ... } — block writes to
#      the client socket directly. Use this for tests that need to drip bytes,
#      stall mid-response, or otherwise control wire timing.
class TestServer
  attr_reader :port

  def self.run(handler = nil, &raw_block)
    new(handler, raw_block).tap(&:start)
  end

  def initialize(handler, raw_block = nil)
    raise ArgumentError, "TestServer needs a handler or a block" unless handler || raw_block

    @handler = handler
    @raw_block = raw_block
    @server = TCPServer.new("127.0.0.1", 0)
    @port = @server.addr[1]
  end

  def start
    @thread = Thread.new do
      Thread.current.report_on_exception = false
      loop do
        client = @server.accept
        Thread.new(client) { |c| serve(c) }
      end
    rescue IOError, Errno::EBADF
      # server socket closed by stop
    end
    self
  end

  def stop
    @server.close
  rescue IOError
    # already closed
  ensure
    @thread&.join(0.5)
  end

  private

  def serve(client)
    request_line = client.gets
    return unless request_line

    method, path, _http_version = request_line.split(" ", 3)
    headers = {}
    while (line = client.gets) && line != "\r\n"
      k, v = line.chomp.split(": ", 2)
      headers[k.downcase] = v if k && v
    end

    if @raw_block
      @raw_block.call(client, method, path, headers)
    else
      response = @handler.call(method, path, headers)
      client.write(format_response(response))
    end
  rescue IOError, Errno::EPIPE, Errno::ECONNRESET
    # client gone mid-write
  ensure
    begin
      client.close
    rescue
      # already closed
    end
  end

  def format_response(response)
    return response if response.is_a?(String)

    status = response[:status] || 200
    reason = response[:reason] || HTTP_REASONS.fetch(status, "OK")
    headers = (response[:headers] || {}).dup
    body = response[:body] || ""

    if response[:chunked]
      headers["Transfer-Encoding"] ||= "chunked"
      body_bytes = encode_chunked(body)
    else
      headers["Content-Length"] ||= body.bytesize.to_s
      body_bytes = body
    end

    head = "HTTP/1.1 #{status} #{reason}\r\n"
    headers.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    head + body_bytes
  end

  def encode_chunked(parts)
    parts = [parts] if parts.is_a?(String)
    out = +""
    parts.each do |p|
      out << "#{p.bytesize.to_s(16)}\r\n#{p}\r\n"
    end
    out << "0\r\n\r\n"
    out
  end

  HTTP_REASONS = {
    200 => "OK",
    301 => "Moved Permanently",
    302 => "Found",
    303 => "See Other",
    307 => "Temporary Redirect",
    308 => "Permanent Redirect",
    404 => "Not Found",
    503 => "Service Unavailable"
  }.freeze
end

module GzipHelper
  module_function

  def gzip(data)
    io = StringIO.new
    gz = Zlib::GzipWriter.new(io)
    gz.write(data)
    gz.close
    io.string
  end
end
