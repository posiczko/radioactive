# frozen_string_literal: true

require "test_helper"

class TestErrors < Minitest::Test
  def test_all_errors_descend_from_radioactive_error
    [
      Radioactive::SchemeError,
      Radioactive::AddressError,
      Radioactive::TimeoutError,
      Radioactive::SizeError,
      Radioactive::RedirectError,
      Radioactive::EncodingError,
      Radioactive::ResponseError
    ].each do |klass|
      assert_operator klass, :<, Radioactive::Error
    end
  end

  def test_response_error_carries_partial_response
    err = Radioactive::ResponseError.new(
      "boom",
      status: 503,
      headers: {"x-foo" => "bar"},
      body: "down"
    )
    assert_equal "boom", err.message
    assert_equal 503, err.status
    assert_equal({"x-foo" => "bar"}, err.headers)
    assert_equal "down", err.body
  end

  def test_response_error_works_without_partial_response
    err = Radioactive::ResponseError.new("transport boom")
    assert_equal "transport boom", err.message
    assert_nil err.status
    assert_nil err.headers
    assert_nil err.body
  end
end
