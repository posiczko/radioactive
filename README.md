# Radioactive

A hardened HTTP fetcher for Ruby. Safe to point at URLs supplied by untrusted users.

## Why

If you've ever written code like:

```ruby
URI.open(user_supplied_url).read
```

for a link preview, image proxy, webhook delivery, or metadata extraction, you have a server-side request forgery (SSRF) vulnerability. A malicious user can submit a URL that makes your server fetch:

- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` - your AWS instance credentials
- `http://localhost:6379/` - your Redis, potentially executable
- `http://10.0.0.5/admin` - your internal admin panel
- `http://metadata.google.internal/` - your GCP project's tokens

`URI.open` happily fetches all of these. So do most general-purpose Ruby HTTP clients (`Net::HTTP`, `Faraday`, `HTTParty`) - your code sees the response body, the attacker gets your secrets.

Untrusted URLs also expose you to:

- **Slowloris**: a server that drips one byte per second can pin a worker thread.
- **Response bombs**: a 10 GB response will OOM your process.
- **Decompression bombs**: 1 KB of gzip can decompress to 100 MB, OOM'ing you anyway.
- **Redirect-to-internal**: `http://example.com/` → `Location: http://127.0.0.1/` bypasses naive blocklists that only check the original URL.
- **DNS rebinding**: by the time your address check resolves the hostname, the attacker has flipped the DNS record to `127.0.0.1`.

`Radioactive` wraps `Net::HTTP` with defenses for all of these, on by default with zero configuration.

## What it protects against

| Threat                                                              | Default behavior                                                             |
|---------------------------------------------------------------------|------------------------------------------------------------------------------|
| Cloud-metadata exfiltration (`169.254.169.254`)                     | Blocked                                                                      |
| Loopback (`127.x`, `[::1]`)                                         | Blocked                                                                      |
| RFC1918 (`10.x`, `192.168.x`, `172.16-31.x`)                        | Blocked                                                                      |
| IPv6 ULA / link-local / multicast                                   | Blocked                                                                      |
| DNS rebinding                                                       | Resolved IP is pinned; redirects re-validate the new host                    |
| Disallowed schemes (`file://`, `gopher://`, `javascript:`)          | Allowlist: `http`, `https`                                                   |
| Embedded credentials (`http://user:pass@host/`)                     | Rejected                                                                     |
| Slowloris / no-read                                                 | `read_timeout` per chunk + `total_timeout`                                   |
| Response bombs                                                      | `max_size` enforced per chunk, default 2 MB                                  |
| Decompression bombs                                                 | `Accept-Encoding: identity` default; opt-in gzip bounded on **decoded** size |
| Redirect chain DoS                                                  | `max_redirects`, default 3                                                   |
| Redirect to private IP                                              | Each hop re-validated through the full pipeline                              |
| Header CRLF/NUL injection in caller-supplied headers                | Rejected                                                                     |
| Non-canonical IP forms (`http://2130706433/`, `http://0x7f000001/`) | Rejected                                                                     |
| Hostname-spoof TLS bypass                                           | Pin via `http.ipaddr=` so SNI and cert verification still use the hostname   |

What it deliberately does **not** do (use Faraday or HTTParty when you control the destination):

- POST / PUT / DELETE / PATCH - read-only by design
- Cookies, sessions, retries, multipart, basic auth
- HTTP/2, HTTP/3
- Outbound proxy, connection pooling, HTTP caching, circuit breakers

For the full threat model, see [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md).

## Installation

```bash
bundle add radioactive
```

Requires Ruby >= 3.2.

## Quick start

The simplest case mirrors `URI.open`:

```ruby
require "radioactive"

body = Radioactive.open("https://example.com/").read
```

For richer access (status, headers, redirect history), use `fetch`:

```ruby
result = Radioactive.fetch("https://example.com/")
result.status     # => 200
result.body       # => "<!doctype html>..."
result.headers    # => {"content-type" => "text/html", ...}
result.final_url  # => #<URI::HTTPS https://example.com/>
result.hops       # => []  (no redirects)
```

If the URL is unsafe (private IP, disallowed scheme, etc.), the fetch raises a `Radioactive::Error`. Most callers in untrusted-input contexts rescue the base class and degrade gracefully:

```ruby
def fetch_metadata(url)
  Radioactive.open(url) do |io|
    Metadata.parse(io.read)
  end
rescue Radioactive::Error => e
  Rails.logger.warn("metadata fetch refused: #{e.class}: #{e.message}")
  Metadata.empty
end
```

## Configuration

Every option can be passed per-call to `fetch` / `open`, or set on a `Fetcher` instance for reuse.

### Smaller body limit (link previews rarely need 2 MB)

```ruby
Radioactive.fetch(url, max_size: 256_000)
```

### Tighter timeouts (interactive request handlers)

```ruby
Radioactive.fetch(url, total_timeout: 5, max_redirects: 1)
```

### Per-tenant / per-context fetcher instances

```ruby
class TenantFetcher
  def initialize(tenant)
    @fetcher = Radioactive::Fetcher.new(
      max_size: tenant.preview_byte_limit,
      max_redirects: 1,
      total_timeout: 8,
      user_agent: "AcmeBot/1.0 (tenant=#{tenant.id})"
    )
  end

  def call(url) = @fetcher.fetch(url)
end
```

### Streaming large bodies to disk (low-memory)

When you pass a block to `open`, the body streams chunk-by-chunk to a `Tempfile` instead of buffering in memory. Peak per-fetch memory stays at ~16 KB regardless of `max_size`. Three common patterns:

**Stream straight to a destination file** - the most common case. The Tempfile yielded to the block is closed and unlinked when the block returns:

```ruby
Radioactive.open(url, max_size: 50_000_000) do |io|
  File.open(destination, "wb") { |dest| IO.copy_stream(io, dest) }
end
```

**Hash while downloading** - useful for image proxies or content-addressable storage where you want SHA256 of the body without holding the whole thing in memory:

```ruby
require "digest"

digest = Digest::SHA256.new
Radioactive.open(url, max_size: 10_000_000) do |io|
  while (chunk = io.read(64 * 1024))
    digest.update(chunk)
    cache.write_chunk(chunk)
  end
end
sha = digest.hexdigest
```

**Compare against `fetch` for the in-memory case** - keep using `fetch` when you actually want the body in a string (link previews, JSON endpoints, anything that fits comfortably under `max_size`):

```ruby
# Small body, want it in memory: use fetch
result = Radioactive.fetch(url, max_size: 256_000)
JSON.parse(result.body)

# Potentially large body, want to write to disk: use open block form
Radioactive.open(url, max_size: 50_000_000) do |io|
  File.open(destination, "wb") { |dest| IO.copy_stream(io, dest) }
end
```

If the body grows past `max_size` during streaming, `Radioactive::SizeError` is raised mid-read and the partially-written Tempfile is unlinked before the exception propagates.

## More advanced

### Custom address blocklist

The default `private_ranges` blocks 25 CIDR ranges (RFC1918, loopback, link-local, IPv6 ULA, etc.). To allow loopback specifically - e.g. when running against a local development server - without disabling all checks:

```ruby
require "ipaddr"

ranges = Radioactive::AddressCheck::DEFAULT_PRIVATE_RANGES.reject do |r|
  r.include?(IPAddr.new("127.0.0.1"))
end

Radioactive::Fetcher.new(private_ranges: ranges)
```

For tests, there's an explicit "skip the address check" shortcut. Don't use it in production:

```ruby
Radioactive::Fetcher.new(allow_private: true)
```

### Opting into compressed responses

The default `accept_encoding: "identity"` rejects compressed responses to defend against decompression bombs. If you trust the destination enough to opt in (and accept that `max_size` then applies to the *decoded* body):

```ruby
Radioactive.fetch(url, accept_encoding: "gzip")
```

### Custom request headers

```ruby
Radioactive.fetch(url, headers: {
  "Accept" => "application/json",
  "X-Trace-Id" => trace_id
})
```

`Host`, `User-Agent`, and `Accept-Encoding` are reserved. Other headers go through after CRLF/NUL validation - invalid values raise `SchemeError` before the socket opens.

## Errors

Every defense raises a distinct subclass of `Radioactive::Error`. Callers in untrusted-input contexts typically rescue the base class:

```ruby
begin
  Radioactive.fetch(user_supplied_url)
rescue Radioactive::Error => e
  log_and_degrade(e)
end
```

If you need to handle specific failure modes:

| Class | Raised when |
|---|---|
| `Radioactive::SchemeError` | Disallowed scheme, missing host, embedded credentials, non-canonical IP literal, or CRLF/NUL in a caller-supplied header |
| `Radioactive::AddressError` | DNS resolution failed, or any resolved address is in `private_ranges` |
| `Radioactive::TimeoutError` | `open_timeout`, `read_timeout`, or `total_timeout` exceeded |
| `Radioactive::SizeError` | `Content-Length` exceeds `max_size`, or the body grows past `max_size` mid-stream |
| `Radioactive::RedirectError` | `max_redirects` exhausted |
| `Radioactive::EncodingError` | Server returned an unexpected `Content-Encoding`, or gzip decoding failed |
| `Radioactive::ResponseError` | Non-2xx status, or transport-level failure (TLS error, connection reset) |

`ResponseError` carries `#status`, `#headers`, and `#body` of the partial response when applicable, so you can react to specific HTTP errors:

```ruby
begin
  Radioactive.fetch(url)
rescue Radioactive::ResponseError => e
  if e.status == 429
    retry_after = e.headers["retry-after"]&.to_i || 60
    sleep retry_after
    retry
  else
    raise
  end
end
```

A common pattern in URL-shortener / link-preview / image-proxy code paths is to log the failure class and continue with empty data - the user submitted a URL we wouldn't fetch, and that's the end of it:

```ruby
def safe_preview(url)
  result = Radioactive.fetch(url, max_size: 512_000, total_timeout: 5)
  parse_preview(result.body, base: result.final_url)
rescue Radioactive::AddressError, Radioactive::SchemeError
  # Caller submitted a URL we won't touch (private IP, weird scheme, etc).
  # Don't surface details - just decline.
  nil
rescue Radioactive::TimeoutError, Radioactive::SizeError, Radioactive::ResponseError => e
  # Caller's URL was reasonable; the destination misbehaved.
  Metrics.increment("preview.refused", tags: {reason: e.class.name.split("::").last})
  nil
end
```

## Testing

When you write tests against code that uses `Radioactive`, you generally want to avoid touching the real network or waiting for real time. The library provides three injection seams for exactly this:

| Option                | Replaces                                | Protocol                                                  |
|-----------------------|-----------------------------------------|-----------------------------------------------------------|
| `resolver:`           | `Resolv` (default)                      | object responding to `getaddresses(host) → Array[String]` |
| `clock:`              | `Radioactive::MonotonicClock` (default) | object responding to `now → Float`                        |
| `allow_private: true` | the address blocklist                   | bool - disables address checks entirely; for tests only   |

### Stubbing DNS

Returning a fixed address per hostname lets you assert exactly what the address-check pipeline sees, without touching real DNS:

```ruby
class StubResolver
  def initialize(map) = @map = map

  def getaddresses(host)
    @map.fetch(host) { raise "unexpected resolve(#{host.inspect})" }
  end
end

resolver = StubResolver.new(
  "ok.example"     => ["8.8.8.8"],    # public - passes the address check
  "evil.example"   => ["10.0.0.1"]    # RFC1918 - blocked by default
)

fetcher = Radioactive::Fetcher.new(resolver: resolver)
```

The "raise on unexpected lookup" pattern is deliberate: it makes tests fail loudly if your code under test resolves a hostname you didn't plan for.

### Stubbing the clock

A `clock` is anything responding to `now → Float`. To force a `total_timeout` to fire deterministically:

```ruby
class StubClock
  def initialize(values) = @values = values.dup
  def now = @values.shift || raise("clock exhausted")
end

# total_timeout = 5; second clock read happens at t=100, well past the deadline.
fetcher = Radioactive::Fetcher.new(
  total_timeout: 5,
  clock: StubClock.new([0.0, 100.0])
)

assert_raises(Radioactive::TimeoutError) { fetcher.fetch("https://ok.example/") }
```

### Running against a real local server

If your test suite spins up an actual HTTP server (Rack, Sinatra, WEBrick) on `127.0.0.1`, the default `private_ranges` blocks it. Two options:

```ruby
# Coarse: skip address checks entirely
Radioactive::Fetcher.new(allow_private: true)

# Fine: allow loopback only, keep RFC1918 / metadata / etc. blocked
require "ipaddr"
ranges = Radioactive::AddressCheck::DEFAULT_PRIVATE_RANGES.reject do |r|
  r.include?(IPAddr.new("127.0.0.1"))
end
Radioactive::Fetcher.new(private_ranges: ranges)
```

The fine-grained version is preferable when you want the test to still fail if your code accidentally tries to reach AWS metadata or RFC1918, even from inside the test suite.

### Asserting on specific failure modes

Each defense raises a distinct `Radioactive::Error` subclass, so tests can pin down exactly *why* a fetch failed. RSpec:

```ruby
expect { Radioactive.fetch("http://10.0.0.1/") }.to raise_error(Radioactive::AddressError)
expect { Radioactive.fetch("file:///etc/passwd") }.to raise_error(Radioactive::SchemeError)
expect { Radioactive.fetch("http://2130706433/") }.to raise_error(Radioactive::SchemeError, /numeric host/)
```

Minitest:

```ruby
assert_raises(Radioactive::AddressError) { Radioactive.fetch("http://10.0.0.1/") }
err = assert_raises(Radioactive::SchemeError) { Radioactive.fetch("http://2130706433/") }
assert_match(/numeric host/, err.message)
```

### Testing streaming downloads

If your code uses the `open` block form to stream a body to disk, two things are worth asserting in tests: the right bytes ended up where you expected, *and* that the size cap actually trips when the body is too large. A pattern with a stub resolver and a `Rack`-style local server (using `allow_private: true` for the test):

```ruby
def test_image_proxy_streams_to_disk
  destination = Tempfile.new(["proxied", ".bin"])

  Radioactive.open(@server_url, allow_private: true, max_size: 10_000_000) do |io|
    IO.copy_stream(io, destination)
  end

  destination.rewind
  assert_equal expected_bytesize, destination.size
  assert_equal expected_sha, Digest::SHA256.file(destination.path).hexdigest
ensure
  destination&.close
  destination&.unlink
end

def test_image_proxy_refuses_oversize_body
  # Server returns 500 KB; we cap at 100 KB.
  assert_raises(Radioactive::SizeError) do
    Radioactive.open(@server_url, allow_private: true, max_size: 100_000) do |io|
      io.read
    end
  end
end
```

The block-form `open` unlinks its Tempfile on every exit path - success or `SizeError` - so tests don't have to manage cleanup of *its* internal Tempfile, only their own.

### Testing Radioactive itself

If you're contributing, the test layout is:

- `test/test_*.rb` - Minitest tests, auto-discovered. Each file groups tests by component (`test_address_check.rb`, `test_fetcher.rb` for unit-level, `test_fetcher_http.rb` for integration).
- `test/support/server_fixture.rb` - small `TCPServer`-based HTTP fixture used by the integration tests. Two modes:
  - `TestServer.run(handler)` - handler is `(method, path, headers) → response`, where response is either a raw HTTP response string or a `{status:, headers:, body:, chunked:}` hash.
  - `TestServer.run { |client, method, path, headers| ... }` - block writes directly to the client socket, for tests that need wire-level control (e.g. dripping bytes for slowloris).

Two layers of tests:

- **Unit** (no socket): scheme/credential validation, IP blocklist, dual-A rejection, `total_timeout` deadline trip - all use stubbed `resolver` and/or `clock`.
- **Integration** (real socket): redirect handling, body size cap, `Content-Length` pre-reject, `Content-Encoding` rejection, gzip decode + decoded-size cap, `read_timeout`, slowloris, redirect-to-private revalidation.

Useful commands:

```bash
bundle exec rake                                  # full default: test + lint + types
bundle exec rake test                             # tests only
bundle exec rake test TESTOPTS="--name=/redirect/"  # filter by test name
bundle exec ruby -Ilib -Itest test/test_fetcher.rb  # run one test file directly
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake gem:install`. See [Releasing](#releasing) below for publishing a new version.

## Releasing

A release cuts a new version, tags it in git, and pushes the `.gem` to [rubygems.org](https://rubygems.org). The published gem requires MFA for any push (set in `radioactive.gemspec`), so you'll be prompted for a one-time code.

### Pre-flight

1. `bundle exec rake` exits 0. Tests, lint, and type checks all green.
2. `lib/radioactive/version.rb` bumped to the new version following [SemVer](https://semver.org).
3. `CHANGELOG.md` has a populated section for the new version with a date, and `[Unreleased]` is empty (or its contents have been moved into the new section).
4. Working tree is clean (`rake gem:release` enforces this).
5. You have an active rubygems session: `gem signin` if `gem whoami` returns nothing.

### Cutting the release

```bash
bundle exec rake gem:release
```

This runs, in order:

1. `gem:release:guard_clean` - aborts if there are uncommitted changes.
2. `gem:build` - builds `pkg/radioactive-X.Y.Z.gem`.
3. `gem:release:source_control_push` - creates `git tag vX.Y.Z` and pushes the commit + tag.
4. `gem:release:rubygem_push` - pushes the `.gem` to rubygems.org (this is the step that prompts for your MFA code).

If anything fails midway (e.g. push rejected, MFA timeout), the tag may already be pushed but the gem may not be published. Re-run `bundle exec rake gem:release:rubygem_push` to retry just the publish step.

### After the release

- Open `CHANGELOG.md` and start a fresh empty `## [Unreleased]` section above the just-released version.
- Bump `lib/radioactive/version.rb` to the next anticipated version with a `.dev` or `.alpha` suffix if you want subsequent local builds to be distinguishable from the release.
- Push that commit; future changes accumulate under `[Unreleased]` until the next release.

### Stronger publishing setup (optional)

For a security-focused gem, consider [RubyGems Trusted Publishing](https://guides.rubygems.org/trusted-publishing/) instead of pushing from a developer machine: a tagged commit triggers a GitHub Actions workflow that authenticates to rubygems via OIDC and publishes without any long-lived API key on disk. Removes the "stolen laptop = compromised gem" risk and complements the MFA requirement.

## Type checking (RBS + Steep)

This gem ships type signatures in `sig/radioactive.rbs` and uses [Steep](https://github.com/soutaro/steep) to verify them. If you're new to Ruby type checking, here's what each piece is doing.

### The 30-second mental model

- **RBS** is a separate file format that says *what* your code looks like (method names, parameter types, return types). It's just declarations - like a header file - and it does **not** affect how Ruby runs. The actual sigs live in `sig/radioactive.rbs`.
- **Steep** is a type checker. It reads `lib/*.rb` and compares it to `sig/*.rbs`, and complains when the two disagree (e.g. a method's actual return type doesn't match what the sig promised).

So: `sig/` is a contract; Steep verifies the contract. Neither runs in production - both are dev-time tools.

### Why we bother

1. **API drift protection.** If we rename a public method or change a return type and forget to update the sig, `rake types` fails. The sig file becomes load-bearing instead of decorative.
2. **Better editor support for users.** Consumers of the gem who use Steep or RBS-aware editors (RubyMine, VS Code with Sorbet/Steep extensions) get autocomplete and inline errors when they call `Radioactive.fetch(...)` with the wrong arguments.

### The commands you'll use

| Command                           | What it does                                                                                                 |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------|
| `bundle exec rake types:validate` | Sanity-checks the RBS file itself - catches typos like referring to a class that doesn't exist. Fast.        |
| `bundle exec rake types:check`    | Runs Steep, which compares `lib/` against `sig/`. **This is the one that catches real drift.** Slower (~5s). |
| `bundle exec rake types`          | Runs both. Also part of the default `rake` task, so `bundle exec rake` now runs `test` + `lint` + `types`.   |

### When do I need to touch `sig/radioactive.rbs`?

Whenever the **public API** changes:

- Adding/removing/renaming a public method (`Radioactive.foo`, `Fetcher#bar`, etc.)
- Adding/removing/renaming a configuration option (the kwargs on `Fetcher.new`, `fetch`, `open`)
- Changing what a public method returns or accepts

You usually do **not** need to update sigs for private-method changes - the `private` block in the sig is loosely typed and just exists so Steep stops complaining about internal call sites. If you add a brand-new private method and Steep grumbles "Method X is not declared," add a line for it (with `untyped` for unknown types if you're not sure).

### When Steep complains

The most common failure modes:

- **"Cannot pass a value of type X as an argument of type Y"** - your code passes the wrong type somewhere. Either fix the code or, if the code is correct and the sig is too narrow, widen the sig.
- **"Method X is not declared in RBS"** - you added a method but didn't add a sig line. Add one (in the `private` block if it's internal).
- **"Cannot find the declaration of constant: `Foo`"** - Steep doesn't know about a class from a stdlib or external gem. If it's stdlib, add `library "foo"` to `Steepfile`. If it's a gem, you'll need an inline stub (see `sig/zeitwerk.rbs` for an example).

When in doubt, paste the error into a search engine - Steep's diagnostic IDs (e.g. `Ruby::ArgumentTypeMismatch`) make for good search terms.

### Files involved

- `sig/radioactive.rbs` - the signatures themselves.
- `sig/zeitwerk.rbs` - a tiny stub for the one external gem we use at the entry point.
- `Steepfile` - Steep's config (which signatures to load, which Ruby files to check).
- `lib/tasks/types.rake` - the rake tasks.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/radioactive.

### Before opening a PR

1. **Run the full check locally.** `bundle exec rake` runs tests, RuboCop, and the type check (`rbs validate` + `steep`). All three must pass.
2. **Update the spec if you're changing behavior.** The contract lives at [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md). Code and spec drift is a bug - fix them in the same commit.
3. **Update the signatures if you're changing the public API.** Any change to a public method on `Radioactive`, `Fetcher`, `Result`, or any error class needs a matching update in `sig/radioactive.rbs`. The Type checking section above covers what to do; `bundle exec rake types` will tell you when something's off.
4. **Add a test.** Especially for security-sensitive paths: every defense in the threat model should have a test that proves the failure path actually closes. See `test/test_fetcher.rb` and `test/test_fetcher_http.rb` for patterns.

### Security issues

Please report security-sensitive issues privately rather than via a public GitHub issue. (TODO: contact email or GitHub Security Advisory link.)

### Style

The project uses [`standard`](https://github.com/standardrb/standard) (via RuboCop) for formatting. `bundle exec rake lint` reports issues; `bundle exec rake lint:rubocop:autocorrect` fixes the autocorrectable ones.
