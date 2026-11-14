# ClientHello templates

`zprobe tls --template FILE` takes a captured TLS record (the raw bytes of one ClientHello, starting with `16 03 01`).
zprobe replaces the SNI, fixes all lengths, and randomizes the client random and session id.
Key shares are kept as captured.

With no `--template` (or `--template builtin`), zprobe builds a Chrome-like ClientHello itself:
GREASE, X25519MLKEM768 (valid-form ML-KEM-768 key, about 1.5 KB, two TCP segments), ALPN h2/http1.1.

Capture a real one, for example: `tcpdump -i any -w ch.pcap 'tcp port 443'`, then extract the first
client TLS record with tshark (`-Y tls.handshake.type==1 -T fields -e tls.record`...) and save the bytes here.
To get the built-in one as a file: `zprobe hello --host example.com > builtin.bin`.
