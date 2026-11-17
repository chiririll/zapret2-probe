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
zprobe check --check NAME [--arg K=V ...] [--phase prepare] [--checks DIR ...]   # a Lua check script, needs WITH_LUA=1
zprobe check-info [--checks DIR ...]                                              # the scripts on the search path, as JSON
zprobe batch [--parallel 4] [--pace-ms 200] < jobs.jsonl
zprobe hello --host example.com > clienthello.bin
```

Exit status: 0 if every probe was `ok`, 1 otherwise, 2 for usage errors.

## Output

```json
{"proto":"tls","host":"example.com","ip":"104.20.23.154","port":443,"repeat":2,"ok":2,"class":"ok",
 "counts":{"ok":2},"median_ms":53,"results":[{"class":"ok","ms":52,"connect_ms":19,"detail":"server_hello"}, ...]}
```

Classes: `ok`, `rst`, `timeout`, `alert`, `forged`, `dns_spoofed`, `unreachable`, `error`, `stalled`, and, from `check` only,
`inconclusive` (the script could not test what it is for).
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

## Check scripts (Lua)

What "works" means for a service is a Lua script; C keeps the transport (sockets with `SO_MARK`, TLS through mbedtls, QUIC
Initial, DNS, timeouts, byte counting, the classes above). A script is `NAME.lua` in a directory given with `--checks`
(repeatable, first match wins; default `/etc/zapret2/autotune/checks`, `/usr/share/zapret2/autotune/checks`,
`/usr/share/zapret2/probe/checks`). It returns a table:

```lua
return {
  title = "Reachability",
  protos = { "tls", "quic", "http" },            -- the first is the default for `proto`
  args = { host = { required = true }, path = { default = "/" }, min_bytes = { type = "number", default = 65536 } },
  prepare = function(p, args) ... end,           -- optional, once per round, see below
  check = function(p, args) ... return p:ok("detail") end,
}
```

`args` types are `string` (default), `number`, `bool`, `list`. zprobe fills defaults, converts, and answers `bad_arg_NAME`,
`missing_arg_NAME` or `bad_proto_X` (class `error`) before the script runs. `proto`, `stage` (default `confirm`) and
`prepared` are always accepted. `check-info` prints each script's `title`, `protos`, `args` and whether it has `prepare`.

Primitives on `p` (a table argument; each uses the job's mark and timeout, cut to the time the job has left, records a
step, and returns a table with `class`, `detail`, `ms`, `ip`):

| Call | Extra fields in, extra fields out |
|---|---|
| `p:dns(host)` | in `server`, `ref`; out `answers` |
| `p:tls{host}` | in `ip`, `port`, `template`; ClientHello, waits for a ServerHello |
| `p:quic{host}` | in `ip`, `port`; QUIC Initial |
| `p:http{host, path}` | plain HTTP; out `status` |
| `p:fetch{url \| host+path}` | HTTPS through mbedtls. In `ip`, `port`, `method`, `headers` (table), `body`, `min_bytes` (0: until the response ends), `max_body`, `stop = "headers"`. Out `status`, `headers` (lower-case keys, repeated ones joined with `, `), `body` (decoded, up to `max_body`; counting goes on past it), `bytes` (on the connection, handshake included), `hs_ms`. One request, no repeating of short pages. |
| `p:udp{host, port, payload, wait_ms}` | out `replies` (list of strings, may be empty) |
| `p:report(key, value)` | adds to `data` in the output; a second report of a key replaces it. Strings, numbers, booleans and tables. |
| `p:ok(d)`, `p:fail(class, d)`, `p:inconclusive(d)` | the verdict; the script may return it or only call it |

Output is the shape of the other commands (`class`, `ok`, `counts`, `median_ms`, `results[]`); each result adds `steps` (every
primitive: host, ip, class, detail, ms, bytes, status) and `data`. `prepare` runs as a separate job (`"phase":"prepare"`, once;
its `data` is what the caller passes back as `args.prepared`). Batch job: `{"id":"17","cmd":"check","check":"youtube-video",
"mark":"0x08010000","timeout":8000,"repeat":2,"args":{"proto":"tls","stage":"confirm","video":"..."}}`. A check job always runs in its
own process, also with `--parallel 1`.

The sandbox: one `lua_State` per job, created after `--user` dropped root. Open: `base` (without `dofile`, `loadfile`, `load`,
`loadstring`, `print`, `getfenv`, `setfenv`), `string` (without `dump`), `table`, `math`. Not open: `io`, `os`, `package`, `debug`,
and on LuaJIT `ffi`, `jit`, `bit`. `require NAME` loads `lib/NAME.lua` from the same directories (`json`, `url` ship with zprobe); bytecode
is refused. Limits: an instruction-count hook ends a looping script at the job's deadline (`timeout` + 2 s per repeat, class `error`, detail
`check_timeout`), an `alarm()` ends anything blocked outside that, and a call's timeout can never exceed the time left. Memory is not
limited. Write scripts in the common subset of Lua 5.1 and 5.3 (no `//`, no bit operators, no reliance on integer/float); `make test`
runs `tests/scripts/run.lua` under the interpreter in `LUA_BIN`.

Shipped: `checks/generic.lua` (`tls`: a ServerHello on `screen`, a download on `confirm`; `quic`; `http`; a short redirect to
another registrable domain is `forged`, to the same one it is followed once), `checks/lib/json.lua`, `checks/lib/url.lua`.

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
make WITH_LUA=1 [LUA_PKG=luajit|lua5.3 | LUA_CFLAGS=... LUA_LIB=...]   # adds `check`; same library as nfqws2
make test       # unit tests (RFC 9001 key vectors, classification, parsing) + loopback tests with fake servers
```

Crypto for QUIC (AES-GCM, HKDF) comes from the pinned `upstream/zapret2` submodule (`nfq2/crypto`), not a copy.

## Not done yet

- DoH for `dns`.
- `p:http` returns no headers; a `check` build has no memory limit for scripts.
- TTL-based detection of forged TLS answers (needs IP_RECVTTL on raw sockets).
- `batch` uses forked workers, not a single epoll loop.
- The built-in ClientHello has a fixed extension order (Chrome shuffles it); use `--template` with a capture to match a specific client.
- No netns integration test yet: `make test` covers loopback only.
