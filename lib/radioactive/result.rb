# frozen_string_literal: true

module Radioactive
  Result = Data.define(:url, :final_url, :status, :headers, :body, :hops)
end
