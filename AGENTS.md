# Xray maintenance

When upgrading the embedded Xray core, follow [docs/xray-upgrades.md](docs/xray-upgrades.md). Pin an official release commit, align the Go/Docker toolchain, preserve V2bX's custom dispatcher behavior, and run both configuration regression checks and real H2/H3 split-entry tests plus the combined-core build. Keep panel aliases at `core/xray/compat.go`; do not silently drop legacy settings or translate removed crypto modes into different modes. Updating an upstream dependency alone is not a completed upgrade.

Create files and directories with English names. Do not deploy to a remote server solely because a compatibility workflow passes; deployment follows the user's current authorization.
