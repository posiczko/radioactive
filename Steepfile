# frozen_string_literal: true

D = Steep::Diagnostic

target :lib do
  signature "sig"
  check "lib"

  # Stdlib signatures we use directly. Steep ships these with the rbs gem.
  library "uri"
  library "ipaddr"
  library "stringio"
  library "tempfile"
  library "net-http"
  library "openssl"
  library "resolv"
  library "zlib"

  # Empty hash/array literals would force every internal variable initialization
  # to carry an inline RBS annotation comment. Silence — they're advisory.
  configure_code_diagnostics do |hash|
    hash[D::Ruby::UnannotatedEmptyCollection] = nil
  end
end
