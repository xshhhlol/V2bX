# Xray core upgrades

## Current baseline

- Official XTLS/Xray-core **v26.11.9**, commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9`.
- Go module: `v1.260327.1-0.20261109052709-676eaf66f8f0`. This is the Go pseudo-version of the release commit, not the March release. The upstream `v26.11.9` executable tag has no corresponding `v1.261109.0` module tag.
- Go **1.27.3**; release CI reads `go.mod`. Keep the Docker builder version aligned.
- The core is compiled into V2bX. Replacing a standalone `xray` executable does not upgrade V2bX.

## Compatibility boundaries

`core/xray/compat.go` translates panel JSON aliases before decoding upstream structs. Legacy `sessionPlacement` and `sessionKey` map to `sessionIDPlacement` and `sessionIDKey`, including `extra` and nested download transports. Explicit current names win. Unknown fields are preserved so future upstream additions can pass through.

This boundary only affects V2bX server configuration. Client subscription exporters must emit fields supported by their client core. For new advanced configurations, use the current field names and verify the client version. Do not enable newly introduced session encodings until both ends support them.

The custom dispatcher must retain V2bX authentication, rate/device limits, traffic counters and connection revocation. Compare upstream `app/dispatcher` and `common/session` on every update; do not replace our dispatcher wholesale. Domain/IP sniffing exclusions now use upstream geodata matchers.

Shadowsocks `none`/`plain` is unsupported by the official core; do not silently substitute another cipher. Legacy `DisableIVCheck: true` remains unsupported. Custom inbound/outbound JSON must satisfy the pinned core's validation.

The current Freedom outbound blocks private destinations by default, including loopback. Keep that default in production; installations intentionally proxying private services must review their custom outbound `finalRules`. The echo integration test explicitly allows only its temporary `127.0.0.1` TCP port.

The sing core and Xray share `github.com/xtls/reality`. Our sing fork accepts both the old raw-byte private key and the newer `*ecdh.PrivateKey` API. Keep that compatibility patch when updating the sing dependency; the combined-core build is required even for Xray-only upgrades.

## Upgrade procedure

1. Check the official stable release and its Go requirement. Resolve its exact commit; pin that commit's Go module version. Avoid `@main` or automatic production upgrades.
2. Update `go.mod`, `go.sum`, and the Docker Go version together. Release CI gets its Go version from `go.mod`. Use `GOWORK=off` so a parent workspace cannot override published dependencies.
3. Review changes to `infra/conf`, `common/session`, `features`, `proxy`, TLS and QUIC dependencies. Add aliases at the JSON boundary only when their semantics match; reject removed features explicitly.
4. Run the **Xray upgrade compatibility** workflow. Pull requests check the pinned module; manual runs accept an official tag/commit, or default to the latest stable release. Scheduled runs check latest stable every Monday on the repository's default branch. The workflow changes only its disposable checkout, uploads the dependency diff and never publishes. GitHub must have Actions/scheduled workflows enabled.
5. Run the release validation matrix as well. The full build includes sing, Xray and Hysteria2 to catch shared dependency conflicts. Check Linux amd64/arm64 artifacts and exercise an existing client against a staging server, including real certificate validation, panel refresh, traffic reporting and removed users.
6. Only then publish a versioned V2bX release. Keep the previous executable/configuration for rollback. A passing scheduled check is evidence for review, not permission to deploy.

Local core checks (Go version from `go.mod`):

```sh
export GOWORK=off GOEXPERIMENT=jsonv2
go test -race -tags xray ./core/xray ./core/xray/app/dispatcher ./conf -run '^TestX(HTTPValidation|ray.*)$' -timeout 90s
go test -tags xray ./core/xray -run '^TestXHTTP.*RoundTrip$' -count=1 -timeout 90s
go build -tags "sing xray hysteria2 with_quic with_grpc with_utls with_wireguard with_acme with_gvisor" -o /tmp/V2bX .
```

Real sessions are also tested without `-race`: v26.11.9 still exhibits an upstream TLS certificate hot-reload race. The upgrade workflow also performs an informational full session race probe and uploads its log; this known upstream failure does not suppress the required configuration/dispatcher race tests. V2bX's own concurrent connection revocation bug was fixed and has a race regression test. Recheck upstream races with each upgrade; do not interpret a functional pass as a clean full race result.
