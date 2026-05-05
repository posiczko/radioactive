# frozen_string_literal: true

require "test_helper"
require "uri"

class TestRadioactive < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Radioactive::VERSION
  end

  def test_module_exposes_fetch_and_open
    assert_respond_to Radioactive, :fetch
    assert_respond_to Radioactive, :open
  end

  def test_result_is_frozen_data_with_expected_members
    r = Radioactive::Result.new(
      url: URI("https://example.com"),
      final_url: URI("https://example.com"),
      status: 200,
      headers: {"content-type" => "text/plain"},
      body: "hi",
      hops: []
    )
    assert_equal 200, r.status
    assert_equal "hi", r.body
    # Data instances are deeply immutable
    assert r.frozen?
  end
end
