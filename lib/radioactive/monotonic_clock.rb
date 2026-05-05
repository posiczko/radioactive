# frozen_string_literal: true

module Radioactive
  module MonotonicClock
    def self.now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end
  end
end
