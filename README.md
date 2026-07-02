# rdns

A DNS server written from scratch in Rust: authoritative server, caching
forwarder, and validating resolver. The RFC 1035 wire format is implemented
directly — no third-party DNS libraries.

## Running

```sh
cargo build --release
./target/release/rdns --config rdns.example.toml
dig @127.0.0.1 -p 5300 www.example.lab A
```

See `rdns.example.toml` for all options (listen address, upstream failover,
recursion ACL, rate limiting, cache size, API, transfers, DNSSEC, TLS).
`kill -HUP` reloads zones and RPZ rules from disk.

## Management API

A REST API for zone and record management. Authentication is by the `X-API-Key`
header.

```sh
K='X-API-Key: changeme'; B=http://127.0.0.1:8081/api/v1
curl -H "$K" $B/zones                   # list zones
curl -H "$K" $B/zones/example.lab.      # zone detail with rrsets
curl -H "$K" -X PATCH $B/zones/example.lab. \
  -d '{"rrsets":[{"name":"db.example.lab.","type":"A","ttl":120,"records":["10.0.0.77"]}]}'
curl -H "$K" -X POST $B/zones -d '{"name":"new.lab.","rrsets":[...]}'   # create a zone
curl -H "$K" -X DELETE $B/zones/new.lab.
curl -H "$K" $B/statistics              # server counters
```

Changes take effect immediately (the SOA serial is bumped automatically), are
persisted to `zone_dir` as zone files, notify configured secondaries, and
re-sign the zone when DNSSEC is enabled.

## Resolution modes

`recursion.mode = "forward"` (default) sends cache misses to the configured
upstreams with failover. `recursion.mode = "recursive"` instead resolves
iteratively from the IANA root hints, following NS referrals and glue down the
delegation tree with no upstream — a full recursive resolver. Both modes share
the cache, singleflight, RPZ, and DNSSEC validation. Conditional forwarding
(`[[forward]]`) overrides the mode for specific zones.

## Record types

The typed rdata parsers cover A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, and
CAA. Any other type — TLSA, SVCB, HTTPS, NAPTR, DS, DNSKEY, … — is authorable in
zone files and over the API using the RFC 3597 generic form
(`name TTL IN TYPE52 \# <len> <hex>`), and all types forward and cache
transparently.

## Dynamic updates (RFC 2136)

`[update] allow` enables `nsupdate`-style dynamic updates over UDP and TCP:
record additions and deletions, prerequisite checks, gated by a client ACL and
optional TSIG. A successful update bumps the SOA serial, journals the delta for
IXFR, persists the zone, re-signs it when DNSSEC is enabled, and NOTIFYs
secondaries.

## Zone transfers and secondaries

- **Primary**: serves AXFR (gated by `transfer.allow`) and IXFR (incremental,
  from an on-disk journal), and sends NOTIFY when a zone changes. Interoperable
  with BIND9 as a secondary.
- **Secondary**: declare `[[secondary]]` to mirror a zone. The refresh loop
  polls the primary's SOA serial (RFC 1982 arithmetic) and transfers on change;
  incoming NOTIFY triggers an immediate refresh.
- **Conditional forwarding**: `[[forward]]` routes matching queries to
  dedicated upstreams.

## TSIG (RFC 8945)

Register HMAC-SHA256/512 keys with `[[tsig_key]]`. `transfer.require_tsig`
enforces a signature on AXFR/IXFR; `secondary.tsig_key` signs a secondary's
transfer requests. Verified against `dig -y`.

## IXFR (RFC 1995)

A per-zone change journal (written on API edits and transfers) enables
incremental transfers. It is persisted under `journal_dir` and reloaded on
restart. When a client's serial is not in the journal, the server falls back to
a full AXFR.

## DNSSEC

### Online signing

`[dnssec]` signs zones online with ECDSA P-256 (algorithm 13), Ed25519 (15), or
RSA/SHA-256 (8). When a query carries the DO bit, responses include RRSIGs,
DNSKEY at the apex, and NSEC or NSEC3 records for authenticated denial (NXDOMAIN
and NODATA). The DS record to upload to the parent is printed at startup.

Signatures are refreshed automatically at a third of the validity window (a
background timer), and re-signed on change and on reload, so RRSIGs never
expire without operator action.

Multiple keys are supported for KSK/ZSK separation and key rollover: the DNSKEY
RRset is signed by the SEP (KSK) keys, zone data by the ZSK keys. NSEC3
(`dnssec.nsec3`) uses iterated SHA-1 with a configurable salt and provides
closest-encloser proofs.

Signatures were verified independently with dnspython + pyca/cryptography across
RSA, ECDSA, and Ed25519, for positive answers, DNSKEY, and NSEC/NSEC3 denial.

### Validating resolver

Setting `recursion.validate = true` validates answers against the DNSSEC chain
of trust from the IANA root trust anchor, in both forward and recursive mode.
Each rrset is checked against its own signer's keys (so cross-zone CNAME chains
validate correctly); negative answers are authenticated through their NSEC/NSEC3
records including range coverage and closest-encloser proofs; and insecure
delegations are only accepted when the absence of a DS is itself proven by the
parent's NSEC/NSEC3 (including opt-out), closing the downgrade gap. Securely-
validated answers set the AD bit — preserved across cache hits — while forged or
broken chains return SERVFAIL and provably-unsigned zones pass through.

Verified against the live internet: valid signatures (ECDSA and RSA, including
1024-bit ZSKs) set AD on both positive and NXDOMAIN/NODATA answers, while
`dnssec-failed.org` and `sigfail.verteiltesysteme.net` return SERVFAIL.

## DNS-over-TLS and DNS-over-HTTPS

- **DoT** (RFC 7858): `tls.dot_listen`. Verified with `dig +tls` over TLS 1.3.
- **DoH** (RFC 8484): `tls.doh_listen`. Serves both HTTP/2 (negotiated via ALPN
  `h2`) and HTTP/1.1; GET (`?dns=base64url`) and POST (`application/dns-message`).
  Verified with `dig +https`, `curl --http2`, and HTTP/1.1 clients.

Certificates come from `tls.cert`/`tls.key` (PEM); a self-signed certificate is
generated when they are omitted.

## Performance

N UDP workers share the port via SO_REUSEPORT, and queries answerable from zones
or the cache are resolved inline in the receive loop with no task spawn. Same
zone, authoritative-only, dnsperf for 10 seconds on 48 cores:

| | BIND9 9.18 | rdns |
|---|---|---|
| QPS (T8 c32) | 509k | **650k (+28%)** |
| QPS (T16 c64) | 611k | **913k (+49%)** |
| Mean latency (T16) | 750µs | **495µs** |

## Layout (Cargo workspace)

```
crates/
  dns-proto     wire format: name compression, messages, EDNS0, TSIG/DNSSEC canonical form
  dns-zone      zone-file parsing/serialization, authoritative lookup, rrset editing
  dns-cache     TTL cache with negative caching (RFC 2308) and serve-stale (RFC 8767)
  dns-metrics   atomic counters
  dns-guard     recursion ACL (CIDR) and per-client rate limiting
  dns-tsig      TSIG HMAC-SHA256/512 (RFC 8945)
  dns-dnssec    DNSSEC signing and validation: DNSKEY/RRSIG/NSEC/NSEC3/DS
  dns-tls       DoT/DoH TLS setup and DoH codec
  dns-xfr       AXFR/IXFR in and out, NOTIFY, journal, secondary refresh
  dns-resolver  resolution (zones → cache → upstream/recursive), singleflight, RPZ, DNSSEC validation
  rdns          binary: UDP/TCP/DoT/DoH listeners, management API, dynamic updates, config
```

Tests: `cargo test` (74).
