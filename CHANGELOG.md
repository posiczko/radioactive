# Changelog

All notable changes to this project will be documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Released]

## [0.1.2] - 2026-05-06

### Fixed

- Dual-stack hosts whose resolver returns AAAA before A on a network without
  IPv6 reachability no longer surface `ResponseError: transport error:
  Errno::EHOSTUNREACH`. `Fetcher#perform_request` now iterates over the full
  pre-validated candidate list returned by `pin_addresses`, advancing to the
  next address on connect-phase transport errors (`Errno::EHOSTUNREACH`,
  `Errno::ENETUNREACH`, `Errno::ECONNREFUSED`, `Net::OpenTimeout`). Errors
  raised after a connection is established (TLS handshake failure, read
  timeout, post-connect `ECONNRESET`, non-2xx response) do **not** trigger
  fallback — silently retrying against a different IP would mask real
  problems.

### Security

- Strict dual-A SSRF rejection is preserved end-to-end. Validation runs
  across the entire resolved address list before any socket opens, so the
  fallback added above cannot weaken the "if any resolved address is in a
  forbidden range, refuse the request" rule. A new HTTP-level test
  exercises the dual-stack-with-one-forbidden-address case to lock this in.
- Caller-supplied header validation now provably runs before any socket
  attempt across the candidate list (regression-tested via the existing
  CRLF / NUL header tests, which previously passed only because the single
  pinned IP refused the connection first).

### Documentation

- `docs/REQUIREMENTS.md` §175 ("DNS resolution and IP pinning") rewritten:
  step 4 now describes a candidate list rather than "the first remaining
  address," and a new step 6 specifies the connect-phase fallback
  semantics, what does *not* trigger fallback, and the exhaustion-error
  shape (`TimeoutError` for `Net::OpenTimeout`, otherwise `ResponseError`).

## [0.1.1] - 2026-05-04

Tooling and documentation only. No runtime behavior changes.

### Changed

- Gem build / install / release rake tasks moved from the top-level namespace
  to `gem:`, matching the project's `lint:` / `types:` / `security:` pattern.
  Use `rake gem:build`, `rake gem:install`, `rake gem:release[remote]`.

### Fixed

- RBS signatures for three Fetcher constants/methods added in 0.1.0 were
  missing from `sig/radioactive.rbs` (`NUMERIC_ONLY_HOST`, `HEADER_INVALID_CHAR`,
  `Fetcher#canonicalize_host`). Caught by Steep on first run of `rake types:check`
  after the security hardening landed.

### Documentation

- New Releasing section in the README covering pre-flight checks, the
  `rake gem:release` flow, and a pointer to RubyGems Trusted Publishing
  for stronger publishing setups.

## [0.1.0] - 2026-05-04

Initial release.

### Added

- `Radioactive.fetch(url, **opts)` returning a frozen
  `Result(url, final_url, status, headers, body, hops)`.
- `Radioactive.open(url, **opts)` returning a `StringIO`; with a block, streams
  the body chunk-by-chunk to a `Tempfile` so peak memory stays at ~16 KB
  regardless of `max_size`.
- `Radioactive::Fetcher` class for reusable per-instance configuration.
- 14 configuration options: `schemes`, `max_size`, `open_timeout`,
  `read_timeout`, `total_timeout`, `max_redirects`, `accept_encoding`,
  `user_agent`, `private_ranges`, `allow_private`, `allow_credentials`,
  `headers`, `resolver`, `clock`.
- Distinct `Radioactive::Error` subclasses for every failure mode:
  `SchemeError`, `AddressError`, `TimeoutError`, `SizeError`, `RedirectError`,
  `EncodingError`, `ResponseError` (the last carrying `#status`, `#headers`,
  `#body` for partial response data).
- RBS signatures in `sig/radioactive.rbs`, validated by `rake types:validate`
  and type-checked against the implementation by `rake types:check` (Steep).

### Security

Defenses on by default with zero configuration:

- **SSRF address blocklist.** 25 CIDR ranges blocked: RFC1918, loopback,
  link-local (incl. cloud metadata at `169.254.169.254`), CGNAT, IPv6 ULA,
  IPv6 link-local, multicast, TEST-NET, Teredo, and reserved ranges.
- **DNS rebinding defense.** Hostname is resolved once; the resolved IP is
  pinned via `Net::HTTP#ipaddr=`; SNI and certificate verification still use
  the original hostname.
- **Strict dual-A rejection.** If *any* resolved address falls in a forbidden
  range, the request is refused (defeats split-horizon SSRF tricks).
- **Redirect re-validation.** Every redirect target is re-run through the full
  pipeline (scheme, credentials, DNS, address check) before the next request.
- **Scheme allowlist.** Default `%w[http https]`; `file://`, `gopher://`,
  `javascript:`, etc. are rejected.
- **Embedded-credential rejection.** URLs with `userinfo` are refused unless
  `allow_credentials: true` is set explicitly.
- **Non-canonical IP rejection.** `http://2130706433/` (decimal) and
  `http://0x7f000001/` (hex) hosts are rejected outright rather than relying
  on resolver behavior.
- **Header CRLF/NUL injection rejection.** Caller-supplied header names and
  values containing `\r`, `\n`, or `\0` are refused before the socket opens.
- **Slowloris and stall defenses.** `read_timeout` per chunk; `total_timeout`
  applied as a wall-clock deadline across all redirects, with per-operation
  timeouts clamped to remaining budget.
- **Response and decompression bombs.** `max_size` enforced per chunk on the
  raw socket; `Content-Length` exceeding `max_size` rejected before any body
  is read; default `Accept-Encoding: identity` rejects compressed responses;
  opt-in `gzip` decompression bounded by **decoded** byte count.
- **TLS verification.** `OpenSSL::SSL::VERIFY_PEER`, no opt-out.
