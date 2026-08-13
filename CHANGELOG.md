# Changelog

## v1.4.9 — Xray/v2rayN/Mihomo compatibility

### Added

- Added compatibility for legacy base64 JSON VMess links and modern AEAD-style VMess URIs.
- Added VLESS XHTTP parsing and Mihomo conversion, including `mode`, `extra`, padding, upload/session options, and XMUX/reuse settings.
- Added support for packet encoding, encryption, IPv6 endpoints, uTLS, REALITY, ECH, certificate pin (`pcs`), and certificate-name verification (`vcn`).
- Added an end-to-end subscription test that validates HTTP routes, generated Clash YAML, and generated sing-box JSON with real Mihomo and sing-box executables.
- Added the compatibility and functional test report at `docs/compatibility-test-report.md`.

### Changed

- Improved Clash/Mihomo conversion for WS, HTTPUpgrade, gRPC, HTTP/H2, TLS, IPv6, numeric, and modern XHTTP fields.
- Filtered XHTTP and Xray-only TLS metadata out of sing-box JSON profiles.
- Derived a separate Clash external-controller secret from each subscriber secret.
- Disabled TUN by default in generated Clash profiles while retaining profile persistence and IPv6-capable DNS defaults.
- Documented the tested compatibility boundary and remaining GUI/live-node limitations.

### Security

- Preserved certificate verification when a certificate pin or verified certificate name is available.
- Kept `allowInsecure` as a fallback only when no certificate pin can be generated.
- Avoided exposing panel or raw subscription credentials in generated Clash controller settings.

### Verification

- `go test ./... -count=1`
- `npm run build`
- `git diff --check`
- Mihomo Meta v1.19.29: generated Clash profile accepted by `mihomo -t`.
- sing-box v1.13.16: generated JSON accepted by `sing-box check`.

## v1.4.8

See the [v1.4.8 GitHub release](https://github.com/HeadStone1/s-ui/releases/tag/v1.4.8).
