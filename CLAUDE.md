# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this gem is

Radioactive is a hardened HTTP fetcher for URLs supplied by untrusted users — a near drop-in alternative to `URI.open` for link previews, image proxying, webhook delivery, and metadata extraction. It defends against the SSRF and DoS classes that `URI.open` leaves open (cloud-metadata exfiltration, RFC1918 access, DNS rebinding, slowloris, response/decompression bombs, redirect chains into private addresses, disallowed schemes).

**The spec is `docs/REQUIREMENTS.md` and it is authoritative.** Read it before designing or changing behavior; threat model, public API, defaults, error hierarchy, and explicit non-goals all live there. This file only summarizes things that constrain *how* you write code.

## Status

The scaffold from `bundle gem radioactive` is still mostly untouched: `lib/radioactive.rb` defines only the module and a base `Error` class, `test/test_radioactive.rb` contains the generator's failing `assert false`, and the gemspec metadata (`summary`, `description`, `homepage`, `allowed_push_host`, `source_code_uri`, `changelog_uri`) is still TODO placeholders. Implementation work is greenfield — match the API surface in `docs/REQUIREMENTS.md` rather than inventing one.

Note: the parent directory `/Users/pablo/code/posiczko/CLAUDE.md` documents a different project (Ougai). It does not apply here — Radioactive uses Minitest (not RSpec), Standard (not RuboCop directly), and has no Oj/JrJackson dependency.

## Architectural constraints (from the spec)

These are non-negotiable design choices in `docs/REQUIREMENTS.md`. Don't propose changes that violate them without flagging the spec change first:

- **No global state, no `Radioactive.configure`.** Configuration is per-call or per-`Fetcher` instance. This is explicit in the spec to keep tests sane and avoid cross-tenant leaks.
- **`Net::HTTP` only.** No Faraday, HTTParty, `http.rb`, HTTP/2, HTTP/3, or gRPC. Use `Net::HTTP.start` directly — not `URI.open` — so timeouts and chunked reads are first-class.
- **GET only in v1.** No POST/PUT/DELETE. No WebSocket/SSE.
- **No outbound proxy support in v1**, no connection pooling, no HTTP caching, no retries, no circuit breakers, no MIME sniffing.
- **TLS:** system trust store is authoritative. `verify_mode = VERIFY_PEER` and there is no option to disable it. No TLS pinning, CT, or mTLS.
- **DNS pinning preserves SNI.** Resolve once via the injected `resolver`, validate every resolved address against `private_ranges`, then connect via `http.ipaddr = ip` while leaving `http.address` as the hostname so SNI and cert verification still work. Re-resolve and re-validate on every redirect (defeats DNS rebinding TOCTOU).
- **Strict address check:** if *any* resolved address is in a forbidden range, reject — defeats dual-A-record SSRF.
- **Size enforcement is on the raw socket reader**, not after decompression. Default `Accept-Encoding: identity`; compression is opt-in. Per-chunk size check (16 KB chunks); also reject when `Content-Length` exceeds `max_size` *before* reading the body.
- **All failures raise distinct subclasses of `Radioactive::Error`** so callers can rescue the base class and degrade gracefully. The hierarchy (`SchemeError`, `AddressError`, `TimeoutError`, `SizeError`, `RedirectError`, `EncodingError`, `ResponseError`) is fixed by the spec — don't invent new top-level error classes.
- **`Result` is a frozen `Data.define(:url, :final_url, :status, :headers, :body, :hops)`.** Don't change the shape; downstream code pattern-matches on it.
- **Inject `resolver` and `clock`** rather than calling `Resolv` / `Process.clock_gettime` directly inside fetch logic — the spec calls these out as test seams.
- **Sockets close on every exit path**, success or raise. No leaking connections.

## Commands

- `bin/setup` — install dependencies (wraps `bundle install`).
- `bin/console` — IRB session with the gem preloaded.
- `bundle exec rake` — default task: runs `test` then `standard` (lint). Both must pass.
- `bundle exec rake test` — Minitest suite (driven by `Minitest::TestTask`, picks up `test/**/test_*.rb`).
- `bundle exec rake test TESTOPTS="--name=/pattern/"` — run a single test or matching subset.
- `ruby -Ilib -Itest test/test_radioactive.rb` — run one test file directly without rake.
- `bundle exec rake standard` / `bundle exec rake standard:fix` — lint / autofix.
- `bundle exec rake build` / `install` / `release` — gem packaging tasks (release is maintainer-only and currently blocked by the `allowed_push_host` TODO in the gemspec).

## Layout and conventions

- Code lives under `lib/radioactive/`; the entry point `lib/radioactive.rb` requires `radioactive/version` and defines the `Radioactive` module. New files should be required from there.
- Long-form design docs live in `docs/`. `docs/REQUIREMENTS.md` is the spec; treat it as a contract and update it deliberately (in the same commit as behavior changes) rather than letting code and spec drift.
- RBS signatures live in `sig/radioactive.rbs` — keep them in sync when adding public API.
- Versioning: bump `Radioactive::VERSION` in `lib/radioactive/version.rb` for releases.
- Ruby version: gemspec requires `>= 3.2.0`; `.standard.yml` pins the Standard target to `3.2`. Match that when writing code (no 3.3-only syntax unless you also bump these).
- CI (`.github/workflows/main.yml`) only runs on pull requests — its `push` trigger is wired to a placeholder branch (`.invalid`), so pushes to `main` will not run CI until that's fixed. The matrix currently lists Ruby `'4.0.3'`, which does not exist; expect CI to fail until the version is corrected.
