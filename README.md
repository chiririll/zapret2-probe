# zapret2-probe

`zprobe`: small C tool for checking whether a site is reachable over TLS, QUIC, HTTP and DNS, and *how* it fails
(RST, timeout, TLS alert, forged answer). JSON output. No curl, no OpenSSL. Part of the
[zapret2-openwrt](../zapret2-openwrt/PLAN.md) strategy search, but builds and runs on any Linux.

```
zprobe tls  --host example.com [--ip 1.2.3.4] [--mark 0x08000001] [--repeat 5] [--template FILE]
zprobe quic --host example.com
zprobe http --host example.com [--path /]
zprobe fetch --host example.com [--ip A] [--path /] [--min-bytes 65536] [--ca FILE] [--dump N]   # needs mbedtls
zprobe dns  --host example.com [--server 1.1.1.1] [--ref 8.8.8.8] [--wait 300]
zprobe batch [--parallel 4] [--pace-ms 200] < jobs.jsonl
zprobe hello --host example.com > clienthello.bin
```

Exit status: 0 if every probe was `ok`, 1 otherwise, 2 for usage errors.

## Output

```json
{"proto":"tls","host":"example.com","ip":"104.20.23.154","port":443,"repeat":2,"ok":2,"class":"ok",
 "counts":{"ok":2},"median_ms":53,"results":[{"class":"ok","ms":52,"connect_ms":19,"detail":"server_hello"}, ...]}
```

Classes: `ok`, `rst`, `timeout`, `alert`, `forged`, `dns_spoofed`, `unreachable`, `error`, `stalled`.
The top-level `class` is `ok` only if all repeats are ok, else the most frequent failure.

| Probe | ok | other classes |
|---|---|---|
| tls | ServerHello record | `alert` (TLS alert), `forged` (HTTP text, garbage, wrong version, non-ServerHello), `rst` (RST/FIN before data or while sending), `timeout`, `unreachable` (connect failed) |
| quic | server Initial decrypts (ServerHello or ACK), Retry, or Version Negotiation | `forged` (undecryptable reply), `timeout`, `unreachable` (ICMP) |
| http | valid response | `forged` for 451, redirect to a different registrable domain, non-HTTP data |
| fetch | full TLS handshake, then HTTP `GET` until `--min-bytes` (default 65536) have arrived on the TCP connection, handshake included | `stalled` (handshake done, no data for `--timeout` ms; `bytes` says where it stopped), `forged` (`cert_name`: certificate does not match the host; `cert_untrusted`), `rst`, `alert`, `timeout` (`hs_no_reply`) |
| dns | answer received | `dns_spoofed` (two different replies to one query, or a private/bogon address), `timeout`, `error` (rcode) |

`--ref` adds `differs_from_ref` to the detail when the answers don't overlap. That's only a hint, because CDNs differ by resolver.

`fetch` reports `bytes`, `hs_ms` and the HTTP `status` (any status counts). A short page is requested again on the same
connection until `--min-bytes`; if the server closes first the result is `ok` with detail `short_<bytes>` (inconclusive).
`--dump N` (batch field `dump`) adds `dump` to the result: the status line and headers of the first response, a blank line,
and up to N bytes of its body (chunked bodies decoded, bytes above 0x7e replaced by `?`, so it is plain ASCII). The fetch ends
with the response (`ok`, detail `dump_<length>`) instead of reading to `--min-bytes`. It exists for the controller's "Add by URL".
Expired certificates are ignored on purpose (router clocks are often wrong). The ClientHello comes from mbedtls, not from
a browser template, so `fetch` complements `tls` and does not replace it.

## Batch

One JSON object per line in, one result per line out. Fields: `id` (echoed), `cmd` (default `tls`), `host`, `ip`, `port`,
`mark`, `repeat`, `timeout`, `pace_ms`, `path`, `min_bytes`, `ca`, `server`, `ref`, `template`, `family`. With `--parallel N` each job runs in a
forked worker, so output order is completion order; use `id`.

## Privileges

`--user NAME` drops root after startup. Only `CAP_NET_ADMIN` is kept (for `SO_MARK`), and only if `--mark` is given or the command is `batch`. It refuses `root` and fails if not run as root.

## Isolation marks

`--mark` sets `SO_MARK` on every socket (including the DNS ones), so nft rules can route probe traffic to a separate
nfqws2 instance. It needs `CAP_NET_ADMIN`; without it the probe reports `error: socket_Operation not permitted`.

## Build and test

```
git clone --recurse-submodules <this repo>
make            # build/zprobe, no dependencies, without `fetch`
make WITH_MBEDTLS=1 [MBEDTLS_PREFIX=/usr/local]   # adds `fetch`; links libmbedtls, libmbedx509, libmbedcrypto (3.x)
make test       # unit tests (RFC 9001 key vectors, classification, parsing) + loopback tests with fake servers
```

Crypto for QUIC (AES-GCM, HKDF) comes from the pinned `upstream/zapret2` submodule (`nfq2/crypto`), not a copy.

## Not done yet

- DoH for `dns`.
- TTL-based detection of forged TLS answers (needs IP_RECVTTL on raw sockets).
- `batch` uses forked workers, not a single epoll loop.
- The built-in ClientHello has a fixed extension order (Chrome shuffles it); use `--template` with a capture to match a specific client.
- No netns integration test yet: `make test` covers loopback only.
