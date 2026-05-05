# frozen_string_literal: true

module Radioactive
  class Error < StandardError; end

  class SchemeError < Error; end

  class AddressError < Error; end

  class TimeoutError < Error; end

  class SizeError < Error; end

  class RedirectError < Error; end

  class EncodingError < Error; end

  class ResponseError < Error
    attr_reader :status, :headers, :body

    def initialize(message = nil, status: nil, headers: nil, body: nil)
      super(message)
      @status = status
      @headers = headers
      @body = body
    end
  end
end
