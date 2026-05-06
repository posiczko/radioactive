# Radioactive — Spec

> A hardened HTTP fetcher for radioactive URLs.

## Concept

`Radioactive` is a small Ruby library that wraps `Net::HTTP` to safely fetch
URLs supplied by untrusted users. It is a near drop-in alternative to
`URI.open` for cases like link previews, image proxying, webhook delivery to
user-controlled endpoints, and metadata extraction in URL shorteners.

Out of the box it defends against the SSRF and DoS attack classes that
`URI.open` leaves wide open: cloud-metadata exfiltration, internal-network
probing, DNS rebinding, slowloris, response bombs, redirect chains into
private addresses, and disallowed schemes.

## Goals

- Drop-in surface familiar to Ruby developers (`Radioactive.open(url)`,
  `Radioactive.fetch(url)`).
- Safe-by-default: requires zero configuration to be more secure than
  `URI.open` with sensible defaults.
- Defenses are applied at fetch time, not validation time, so transient
  conditions (DNS rebinding) are caught.
- Each defense is independently overridable for testing or trusted callers.
- All failures raise distinct subclasses of `Radioactive::Error` so callers
  can tell *why* a fetch was refused.
- No global state. Configuration is per-call or per-instance.

## Non-Goals

- Authenticated fetches. Embedded credentials in URLs are stripped or
  rejected; `Authorization` headers are not provided.
- Full-featured HTTP client (cookies, sessions, retries, multipart). Use
  Faraday or HTTParty when you control the destination.
- HTTP/2, HTTP/3, gRPC. `Net::HTTP` only.
  - TLS pinning, certificate transparency, mTLS. The system trust store is
    authoritative.
- Outbound proxy support in v1 (see Out of Scope).

## Threat Model

| Threat                                    | Vector                                                        | Defense                                                                                                                          |
|-------------------------------------------|---------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| Cloud-metadata exfiltration               | `http://169.254.169.254/`, `http://metadata.google.internal/` | Link-local range `169.254.0.0/16` blocked; non-resolvable hosts (`*.internal`) blocked unless their IP passes the address check. |
| Loopback access                           | `http://127.0.0.1:6379/`, `http://[::1]/`                     | `127.0.0.0/8` and `::1/128` blocked.                                                                                             |
| RFC1918 internal access                   | `http://10.x`, `192.168.x`, `172.16-31.x`                     | All RFC1918 ranges blocked.                                                                                                      |
| IPv6 ULA / link-local                     | `fc00::/7`, `fe80::/10`                                       | Both blocked.                                                                                                                    |
| Wildcard / unspecified                    | `0.0.0.0`, `::`                                               | Blocked.                                                                                                                         |
| DNS rebinding (TOCTOU)                    | DNS flips between validation and fetch                        | Resolve once; fetch by pinned IP; pass `Host:` for SNI/vhost; re-resolve and re-validate on every redirect.                      |
| Disallowed schemes                        | `file://`, `gopher://`, `ftp://`, `javascript:`               | Scheme allowlist (default: `http`, `https`).                                                                                     |
| Slowloris / no-read attack                | Server holds connection open, drips bytes                     | `read_timeout` enforced per chunk.                                                                                               |
| Connect-stall                             | Server SYN-drops or holds half-open                           | `open_timeout` enforced.                                                                                                         |
| Response bomb                             | Server returns 10 GB body                                     | `max_size` enforced; reads in chunks; aborts at limit and raises.                                                                |
| Decompression bomb                        | `Content-Encoding: gzip` body decompressing 100x              | `Accept-Encoding` only includes `identity` by default; decoded size also bounded by `max_size` if compression is opted in.       |
| Redirect chain DoS                        | Long redirect chain                                           | `max_redirects` enforced (default 3).                                                                                            |
| Redirect to internal                      | Public host 302s to `127.0.0.1`                               | Each redirect target re-validated through the full pipeline.                                                                     |
| Embedded credentials                      | `http://user:pass@host/`                                      | Rejected by default; opt-in to allow.                                                                                            |
| Malformed URL injection                   | URL with NULs, CRs, fragments used to spoof requests          | URL parsed strictly; only the canonical form is re-emitted.                                                                      |
| Hostname-spoof TLS bypass                 | Connecting by IP defeats cert hostname verification           | `Net::HTTP#ipaddr=` used so SNI/verification still uses the hostname.                                                            |
| Memory pressure from many small responses | All concurrent fetches buffer into memory                     | Streaming API caps memory per fetch at `max_size`; callers can stream to disk via block form.                                    |

### Threats explicitly **not** covered

- **Application-layer side effects on permitted hosts.** If a public URL
  serves dangerous content, `Radioactive` will fetch it.
- **Compromised public CAs / TLS MITM.** Standard system trust store applies.
- **CPU-time DoS via legitimate but expensive content.** A 2 MB HTML
  document can still hammer a downstream parser. Out of scope.
- **Header-based smuggling against intermediate proxies.** No proxy in v1.

## Public API

### `Radioactive.open(url, **opts) → StringIO`
### `Radioactive.open(url, **opts) { |io| ... } → block result`

`URI.open`-compatible surface. Returns a `StringIO` containing the response
body (capped at `max_size`). With a block, yields the same IO and ensures
the underlying connection is closed.

```ruby
require "radioactive"
require "nokogiri"

Radioactive.open("https://example.com") do |io|
  doc = Nokogiri::HTML(io)
  doc.at_css("title")&.text
end
```

### `Radioactive.fetch(url, **opts) → Result`

Rich form. Returns a frozen `Result`:

```ruby
Result = Data.define(:url, :final_url, :status, :headers, :body, :hops)
```

- `url` — the original `URI` requested.
- `final_url` — the `URI` that ultimately served the response (after
  redirects).
- `status` — `Integer` HTTP status of the final response.
- `headers` — `Hash` of response headers (downcased keys).
- `body` — `String`, capped at `max_size`.
- `hops` — `Array<URI>` of every intermediate URL traversed.

### Configuration

Per-call options or via instance:

```ruby
fetcher = Radioactive::Fetcher.new(max_size: 5 * 1024 * 1024, max_redirects: 1)
fetcher.fetch("https://example.com")
```

| Option              | Type                                                 | Default                            | Notes                                                                    |
|---------------------|------------------------------------------------------|------------------------------------|--------------------------------------------------------------------------|
| `schemes`           | `Array<String>`                                      | `%w[http https]`                   | Anything else raises `SchemeError`.                                      |
| `max_size`          | `Integer` (bytes)                                    | `2_097_152` (2 MB)                 | Counts decoded bytes if compression is opted in.                         |
| `open_timeout`      | `Numeric` (sec)                                      | `5`                                | TCP + TLS handshake budget.                                              |
| `read_timeout`      | `Numeric` (sec)                                      | `10`                               | Per-chunk read budget.                                                   |
| `total_timeout`     | `Numeric` (sec)                                      | `30`                               | Wall-clock budget across all redirects. Optional.                        |
| `max_redirects`     | `Integer`                                            | `3`                                | `0` disables redirects.                                                  |
| `accept_encoding`   | `String`                                             | `"identity"`                       | Set to `"gzip"` only if you accept the decompression-bomb risk.          |
| `user_agent`        | `String`                                             | `"Radioactive/<version>"`          | Sent as `User-Agent`.                                                    |
| `private_ranges`    | `Array<IPAddr>`                                      | See defaults below                 | Override the address blocklist.                                          |
| `allow_private`     | `Boolean`                                            | `false`                            | Convenience: disables address checks. **For tests only.**                |
| `allow_credentials` | `Boolean`                                            | `false`                            | If `false`, URLs with `userinfo` raise `SchemeError`.                    |
| `headers`           | `Hash`                                               | `{}`                               | Extra request headers. `Host`, `User-Agent`, `Accept-Encoding` reserved. |
| `resolver`          | object responding to `getaddresses(host) → [String]` | `Resolv`                           | Inject for tests.                                                        |
| `clock`             | object responding to `now → Float`                   | `Process.clock_gettime(MONOTONIC)` | Inject for tests.                                                        |

### Default `private_ranges`

```ruby
%w[
  0.0.0.0/8
  10.0.0.0/8
  100.64.0.0/10           # CGNAT
  127.0.0.0/8
  169.254.0.0/16          # link-local + cloud metadata
  172.16.0.0/12
  192.0.0.0/24
  192.0.2.0/24            # TEST-NET-1
  192.168.0.0/16
  198.18.0.0/15           # benchmarking
  198.51.100.0/24         # TEST-NET-2
  203.0.113.0/24          # TEST-NET-3
  224.0.0.0/4             # multicast
  240.0.0.0/4             # reserved
  255.255.255.255/32
  ::/128                  # unspecified
  ::1/128
  ::ffff:0:0/96           # IPv4-mapped — checked against IPv4 ranges too
  64:ff9b::/96            # NAT64
  100::/64                # discard
  2001::/32               # Teredo (often tunneled to private)
  2001:db8::/32           # documentation
  fc00::/7                # ULA
  fe80::/10               # link-local
  ff00::/8                # multicast
]
```

## Behavior

### URL parsing

1. Parse with `URI.parse`. Reject if parsing fails or the URI lacks a host.
2. Reject if the scheme is not in `schemes`.
3. If `userinfo` is present and `allow_credentials` is `false`, reject.
4. Strip the fragment (servers don't see it; included for clarity in hops).
5. Re-emit the canonical form for the actual request (no smuggled CRs/NULs).

### DNS resolution and IP pinning

1. Call `resolver.getaddresses(host)`. If empty, raise `AddressError`.
2. For each address: parse as `IPAddr`, check against `private_ranges`.
3. If **any** resolved address is in a forbidden range, raise `AddressError`.
   (Strict: defeats dual-A-record SSRF where a host resolves to a public
   *and* private IP. Validation runs across the whole list before any
   socket opens, so the dual-A guard is not weakened by step 6.)
4. Pin the validated addresses, in resolver order, as connection candidates.
5. Construct `Net::HTTP` with the candidate IP via `http.ipaddr = ip`, but
   leave `http.address` as the hostname so SNI and certificate verification
   work normally.
6. Try candidates in order. If the connection attempt fails with a
   connect-phase transport error (`Errno::EHOSTUNREACH`,
   `Errno::ENETUNREACH`, `Errno::ECONNREFUSED`, or `Net::OpenTimeout`),
   advance to the next candidate. This handles dual-stack hosts whose
   resolver returns AAAA before A on a network without IPv6 reachability.
   Errors raised after a connection has been established (TLS handshake
   failure, read timeout, post-connect `ECONNRESET`, non-2xx status) do
   **not** trigger fallback — the server engaged with us and silently
   retrying against a different IP would mask real problems. If every
   candidate fails at connect, raise the last error in its usual shape
   (`TimeoutError` for `Net::OpenTimeout`, otherwise `ResponseError`).

### Connection

- Set `open_timeout`, `read_timeout`, `write_timeout` (Net::HTTP ≥ 2.6).
- For HTTPS: `verify_mode = OpenSSL::SSL::VERIFY_PEER`. No way to disable.
- Send the request with `User-Agent`, `Host`, `Accept-Encoding`, and any
  caller-supplied non-reserved headers.
- Issue an `HTTP GET`. Other methods are not supported in v1.

### Body reading

- Read in chunks of 16 KB. After each chunk, check accumulated size against
  `max_size`. If exceeded, abort the read, close the connection, raise
  `SizeError`.
- If `Content-Length` is present and exceeds `max_size`, raise `SizeError`
  before reading the body.
- If `accept_encoding` is `"identity"` and the response carries
  `Content-Encoding: gzip`/`deflate`/`br`, raise `EncodingError` (the server
  violated the contract).
- If `accept_encoding` opted into compression, decompress streamingly and
  bound the *decoded* size by `max_size`.

### Redirects

- If `Location` is present and the response status is in
  `[301, 302, 303, 307, 308]`:
  - Decrement the redirect budget. If `0`, raise `RedirectError`.
  - Resolve the new URL relative to the current one.
  - Re-validate it through the entire pipeline (scheme, credentials, DNS,
    address). A redirect to `http://127.0.0.1/` is rejected the same way a
    direct request would be.
  - For `303` or `301/302` on a method other than `GET`, downgrade to `GET`
    (RFC 7231); since we only issue `GET`, this is moot.
  - Append the previous URL to `hops`.
- The `total_timeout` budget covers all redirects.
- The `max_size` budget is per-response (only the final body counts).

### Closing

- Whether the call succeeds or raises, the underlying socket is closed
  before returning. No connection pooling in v1.

## Error Hierarchy

```
Radioactive::Error                    StandardError
├── SchemeError                       disallowed scheme or embedded creds
├── AddressError                      DNS failed, or resolved into a blocked range
├── TimeoutError                      open / read / total timeout exceeded
├── SizeError                         body or declared length exceeded max_size
├── RedirectError                     redirect budget exhausted
├── EncodingError                     unexpected Content-Encoding
└── ResponseError                     non-2xx status, or protocol violation
    └── #status, #headers, #body      partial response data when applicable
```

Callers in trust-untrusted-input contexts (URL shorteners, link previews)
typically rescue `Radioactive::Error` and degrade gracefully — no metadata,
no preview, log and move on.

## Examples

**Drop-in replacement for `URI.open`:**

```ruby
def fetch_metadata(url)
  Radioactive.open(url) do |io|
    Metadata.new(Nokogiri::HTML(io.read))
  end
rescue Radioactive::Error => e
  Rails.logger.warn("metadata fetch refused: #{e.class} #{e.message}")
  Metadata.new
end
```

**Rich form with structured result:**

```ruby
result = Radioactive.fetch(url, max_size: 512_000)
LinkPreview.create!(
  href: result.final_url.to_s,
  title: extract_title(result.body),
  status: result.status,
)
```

**Per-tenant configured fetcher:**

```ruby
class TenantFetcher
  def initialize(tenant)
    @fetcher = Radioactive::Fetcher.new(
      max_size: tenant.preview_byte_limit,
      max_redirects: 1,
      total_timeout: 8,
    )
  end

  def call(url) = @fetcher.fetch(url)
end
```

**Test-time relaxation against a local stub server:**

```ruby
RSpec.configure do |c|
  c.before(:each, :allow_local) do
    @fetcher = Radioactive::Fetcher.new(allow_private: true)
  end
end
```

## Implementation Notes (informative)

- **Pinning IP while preserving SNI.** `Net::HTTP` since 3.0 supports
  `http.ipaddr = "1.2.3.4"`. Construct with the hostname for SNI; assign
  the IP for connection. If targeting older Ruby, set `http.address` after
  resolution and override DNS via a Resolver shim.
- **Avoid `URI.open` internally.** Use `Net::HTTP.start` directly so timeouts
  and chunked reads are first-class.
- **Per-chunk size check** has to happen on the *raw* socket reader, not
  after decompression, when compression is disabled. When compression is
  enabled (opt-in), wrap the IO in `Zlib::GzipReader` or
  `Zlib::Inflate.new(-Zlib::MAX_WBITS)` for deflate, and check decoded size
  in the read loop.
- **`Resolv` returns strings**; wrap in `IPAddr` for range checks. Use
  `IPAddr#ipv4_mapped?` to fold IPv6-mapped IPv4 addresses back to IPv4
  range checks.
- **`total_timeout`** can be implemented by capturing `monotonic` on entry
  and rejecting in the redirect loop / chunk loop when the budget is gone.
- **No global config.** Resist the temptation to add `Radioactive.configure` 
  per-call/per-instance keeps tests sane and avoids leaks across tenants.

## Testing Strategy

Three layers:

1. **Unit, isolated.** Inject a `resolver` returning fixed addresses and a
   `Net::HTTP` stub returning canned responses. Cover each error class.
2. **Integration, local.** Run a tiny Sinatra/Rack app on `127.0.0.1`,
   construct a `Fetcher` with `allow_private: true`, and exercise the
   redirect, size-cap, slowloris, and chunked-encoding paths against real
   `Net::HTTP`.
3. **Adversarial.** A test fixture server that:
   - Drips bytes one per second (slowloris) — assert `TimeoutError`.
   - Returns `Content-Length: 999_999_999` — assert `SizeError` *before*
     reading the body.
   - Returns 4 GB of `0x00` chunked — assert `SizeError` mid-read.
   - 302s to `http://127.0.0.1:<port>/` — with `allow_private: false`,
     assert `AddressError`.
   - Returns `Content-Encoding: gzip` of `\0` × 100 MB compressing to 1 KB
     — with default `accept_encoding: "identity"`, assert `EncodingError`.
   - Has dual-A DNS records (one public, one private) via stub resolver —
     assert `AddressError`.

## Out of Scope (v1) / Future Work

- **Outbound proxy support.** Adds a whole class of bypass concerns
  (CONNECT-tunnel target validation, proxy authentication). Punt.
- **POST / PUT / DELETE.** Designed for safe reads. Writes would require a
  whole new threat surface (CSRF on internal APIs, etc.).
- **Connection pooling / keepalive.** Each fetch opens and closes one
  connection. Pooling would require careful per-host policy under SSRF
  constraints.
- **HTTP caching.** None.
- **Circuit breakers.** Caller's responsibility.
- **Concurrency primitives.** No built-in parallel-fetch helper. Use
  `Concurrent::Promises` or `async-http` at the call site, with one
  `Fetcher` per future.
- **WebSocket / SSE.** Specifically rejected.
- **MIME sniffing / content-type-aware behavior.** `Radioactive` returns
  bytes; callers decide what to do.

## References

- RFC 1918 — Address Allocation for Private Internets
- RFC 4193 — Unique Local IPv6 Unicast Addresses
- RFC 6890 — Special-Purpose IP Address Registries
- OWASP — Server-Side Request Forgery Prevention Cheat Sheet
- AWS — IMDSv2 (instance metadata service)
- Janko Marohnić — `down` gem (prior art for safe HTTP downloads)
- Jordan Brock — `private_address_check` gem (prior art for IP allowlisting)
