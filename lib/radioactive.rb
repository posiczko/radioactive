# frozen_string_literal: true

require "zeitwerk"
loader = Zeitwerk::Loader.for_gem
loader.ignore("#{__dir__}/radioactive/errors.rb")
loader.setup

require_relative "radioactive/errors"

module Radioactive
  def self.fetch(url, **opts)
    Fetcher.new(**opts).fetch(url)
  end

  def self.open(url, **opts, &block)
    fetcher = Fetcher.new(**opts)
    block ? fetcher.open(url, &block) : fetcher.open(url)
  end
end
