# VMess compatible hardening in v1.4.9

The sing core now uses bounded downlink shaping for TCP and VMess Mux. UDP
shaping splits writes after datagram encoding, preserving datagram boundaries,
lengths and nonces. Small responses do not spend the split budget. New Mux
streams and writes after at least 500 ms of idle time can reopen the window;
each connection has at most eight windows and `8 * MaxRecords` actual splits.
No artificial delay, cover traffic or nonstandard protocol padding is added.

Concurrent writes share a lock around response encoding and shaping. Handshake
timeouts and cancellation also terminate transports without read deadlines.
The gRPC server now returns from the affected RPC when its connection closes,
unblocking Recv without closing the shared HTTP/2 connection. Successful
authentication disarms the temporary handshake cancellation callback.

Existing clients and negotiated security modes remain supported. Enable the
optional shaping in the node configuration:

```json
"VMessConfig": {
  "TrafficShaping": { "Enable": true }
}
```

Install through the existing V2bX-script installer or run
`V2bX update v1.4.9`. Updates preserve existing configuration, so an existing
disabled shaping setting remains disabled. Request parsing and gRPC lifecycle
fixes apply independently of the shaping flag. The release includes sing,
Xray and Hysteria2 cores, retaining the Xray v26.11.9 baseline.

Validation covers the sing-vmess race suite, Xray v26.3.27 and v26.11.9 client
encodings, legacy/AEAD Mux, UDP boundaries, concurrent write APIs, and real
gRPC timeout followed by a valid RPC on the same transport. Newer Xray removed
none/zero encodings; the old-client matrix continues to exercise them, and
this sing server does not remove their support.

These tests establish compatibility for the tested cores, not every GUI
client or a measured reduction in DPI detection. Uplink characteristics,
small-response lengths, traffic direction, timing and nested TLS handshakes
remain observable. The server cannot alter a bare VMess client's random
initial payload.

The Android release build explicitly permits the existing anet dependency's
IPv6 zone-cache linknames. The cache layout was checked against Go 1.27;
other platforms retain the linker's default checks.
