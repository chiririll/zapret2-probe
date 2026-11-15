# ClientHello templates

`zprobe tls --template FILE` takes a captured TLS record (the raw bytes of one ClientHello, starting with `16 03 01`).
zprobe replaces the SNI, fixes all lengths, and randomizes the client random and session id.
Key shares are kept as captured.

With no `--template` (or `--template builtin`), zprobe builds a Chrome-like ClientHello itself:
GREASE, X25519MLKEM768 (valid-form ML-KEM-768 key, about 1.5 KB, two TCP segments), ALPN h2/http1.1.

Capture a real one, for example: `tcpdump -i any -w ch.pcap 'tcp port 443'`, then extract the first
client TLS record with tshark (`-Y tls.handshake.type==1 -T fields -e tls.record`...) and save the bytes here.
To get the built-in one as a file: `zprobe hello --host example.com > builtin.bin`.

## Bundled templates

`--template NAME` (no slash) loads `<templates dir>/NAME.bin`; the directory is `$ZPROBE_TEMPLATES` or the install dir
(`/usr/share/zapret2/probe/templates`). A name with a slash is a file path.

| Name | Size | Notes |
|---|---|---|
| `www_google_com` | 681 | plain TLS 1.3 hello |
| `vk_com`, `iana_org` | 517 | plain TLS 1.3 hello |
| `vk_com_kyber`, `rutracker_org_kyber` | ~1800 | with a post-quantum key share, spans two segments |

Taken from real browser captures in upstream zapret2 (`files/fake/tls_clienthello_*.bin`, commit `3bae3d2`).
Two upstream files, `google_com_tlsrec` and `iana_org_bigsize`, are not plain hellos and are not included.
