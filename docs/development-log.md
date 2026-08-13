# Development Log

## 2026-08-13 — v1.4.9 compatibility release

### Goal

Bring the subscription conversion path up to date with current Xray/v2rayN sharing fields and make the generated Clash profile usable by Mihomo-based clients such as Clash Verge Rev.

### Investigation

The repository was compared against the current public documentation and repository descriptions for [Xray-core](https://github.com/XTLS/Xray-core), [v2rayN](https://github.com/2dust/v2rayN), [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev), and [Mihomo](https://github.com/MetaCubeX/mihomo). The relevant compatibility boundary was identified as:

```text
subscription links
  -> link parser
  -> sing-box outbound model
  -> Clash/Mihomo or sing-box profile
  -> core configuration validation
```

### Implementation decisions

1. Keep one normalized outbound representation internally so VMess, VLESS, TLS, IPv6, XHTTP, and modern sharing parameters are converted consistently.
2. Emit XHTTP for Mihomo because it is supported by the Clash Meta ecosystem used by Clash Verge Rev.
3. Omit XHTTP from sing-box JSON because this project does not emit a sing-box XHTTP transport for that path; do not hand an unsupported field to another core.
4. Carry Xray certificate pin and certificate-name metadata only through the Xray/Mihomo path, while removing those fields from sing-box JSON.
5. Prefer a certificate SHA-256 pin for self-signed certificates and retain the insecure fallback only where no certificate material is available.
6. Keep generated TUN disabled by default to avoid making profile import an unexpected system-wide network change.
7. Derive the Mihomo controller password from the subscriber secret instead of copying either the panel session secret or the raw subscription credential.

### Test progression

- Unit tests covered modern VMess URI parsing, legacy VMess JSON normalization, XHTTP extras, XMUX aliases, IPv6 formatting, TLS flags, certificate pin generation, and field filtering.
- HTTP functional tests covered authenticated GET, HEAD, subscription headers, invalid credentials, and rejection of the old name-only route.
- Mihomo Meta v1.19.29 accepted the generated Clash YAML with `mihomo -t`.
- sing-box v1.13.16 accepted the generated JSON with `sing-box check`.
- Full Go regression passed with `go test ./... -count=1`.
- Frontend production build passed with `npm run build`.

### Release

- PR #1 merged into `main`.
- Version advanced from the repository release baseline `v1.4.8` to `v1.4.9`.
- This changelog and the compatibility test report were added as release documentation.

### Remaining work

- Run GUI import smoke tests in the release builds of v2rayN and Clash Verge Rev.
- Run one live-node smoke test for each supported transport.
- Re-run the real-core checks whenever bundled core versions are upgraded.
