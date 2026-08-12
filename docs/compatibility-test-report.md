# Xray, v2rayN, Mihomo Compatibility and Functional Test Report

Test date: 2026-08-13

## Scope

This report covers the subscription compatibility update for current Xray sharing fields, v2rayN-style imports, Mihomo profiles used by Clash Verge Rev, and sing-box JSON output.

Reference projects:

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [2dust/v2rayN](https://github.com/2dust/v2rayN)
- [clash-verge-rev/clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)
- [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)

The v2rayN README identifies Xray and sing-box among its supported cores. Clash Verge Rev identifies itself as a Clash Meta GUI and documents its bundled Mihomo core. Therefore, this report treats real-core configuration acceptance as the repeatable compatibility gate for generated profiles, while listing GUI import and live traffic separately as limitations.

## Changes covered

### Link parsing and generation

- Parse legacy base64 JSON VMess links.
- Parse modern AEAD-style VMess URIs.
- Preserve VLESS/VMess `packet-encoding` and encryption options.
- Normalize IPv6 hosts without creating duplicate brackets.
- Parse and emit Xray certificate pin (`pcs`) and certificate-name verification (`vcn`) parameters.
- Avoid treating textual or boolean false values as `allowInsecure=true`.
- Derive a full SHA-256 certificate pin from a configured self-signed server certificate when possible; retain `allowInsecure` only as a compatibility fallback when no pin is available.
- Parse and emit VLESS XHTTP `mode`, `extra`, padding/session/upload parameters, and XMUX data.

### Mihomo and Clash Verge Rev profiles

- Convert VLESS XHTTP to Mihomo `network: xhttp` and `xhttp-opts`.
- Convert XMUX data to Mihomo `reuse-settings`.
- Preserve WS, HTTPUpgrade, gRPC, HTTP/H2, TLS, uTLS, REALITY, ECH, IPv6, packet encoding, and numeric options.
- Derive a dedicated external-controller secret from the subscriber secret with SHA-256 when the base profile enables `external-controller` without a secret.
- Default TUN to disabled, retain persistence settings, and enable IPv6-capable DNS defaults.

### sing-box profiles

- Exclude XHTTP outbounds because this Xray/Mihomo transport is not emitted as a sing-box transport by this project.
- Remove Xray-only certificate pin and certificate-name metadata before serializing sing-box JSON.
- Keep supported outbounds and selector/urltest references consistent after filtering.

## Automated compatibility matrix

| Area | Case | Result |
| --- | --- | --- |
| VMess | Legacy base64 JSON with WS/TLS | Pass |
| VMess | Modern AEAD-style URI | Pass |
| VLESS | XHTTP link with `mode` and JSON `extra` | Pass |
| VLESS | XHTTP XMUX to Mihomo reuse settings | Pass |
| TLS | `pcs` and `vcn` round trip | Pass |
| TLS | False insecure flags remain false | Pass |
| TLS | Self-signed certificate SHA-256 pin generation | Pass |
| Network | IPv6 share-link host formatting/parsing | Pass |
| HTTP | Authenticated raw subscription GET | Pass |
| HTTP | Subscription HEAD and profile headers | Pass |
| HTTP | Invalid secret returns 400 | Pass |
| HTTP | Legacy name-only route returns 404 | Pass |
| Mihomo | Generated WS and XHTTP profile syntax | Pass |
| Mihomo | Derived controller secret | Pass |
| sing-box | Supported WS remains after filtering | Pass |
| sing-box | XHTTP/Xray-only fields are removed | Pass |

## Real-core functional test

The opt-in Go test in `sub/subscription_functional_test.go` exercises this chain:

```text
temporary SQLite database
  -> authenticated Gin subscription route
  -> raw VLESS WS + XHTTP share links
  -> Clash/Mihomo YAML and sing-box JSON generation
  -> real core configuration validators
```

Core versions used:

- Mihomo Meta v1.19.29, Windows amd64
- sing-box v1.13.16, Windows amd64

Commands represented by the test:

```powershell
$env:SUI_MIHOMO_BIN='C:\path\to\mihomo.exe'
$env:SUI_SINGBOX_BIN='C:\path\to\sing-box.exe'
go test ./sub -run '^TestSubscriptionProfilesWithRealCores$' -count=1 -v
```

The generated Mihomo profile passed `mihomo -t -f <profile>`. The generated sing-box profile passed `sing-box check -c <profile>`.

## Regression and build checks

The following checks passed in the development workspace:

```text
go test ./... -count=1
npm run build
git diff --check
```

All Go packages passed. The frontend production build completed successfully.

## Security behavior verified

- Subscription access requires client ID plus subscriber secret.
- The former name-only subscription path does not return data.
- The downloadable Mihomo controller password is derived and is not the panel session secret or the raw subscriber secret.
- Certificate verification is preserved when pins or verified names are available.
- TUN does not become active solely because a user opens or imports the generated default profile.

## Current limitations

- No automated desktop GUI click-through import was performed in v2rayN or Clash Verge Rev.
- No remote proxy endpoint was used, so handshake, latency, DNS resolution through a tunnel, and sustained traffic were not tested.
- Core configuration acceptance proves schema and generated-profile compatibility for the tested versions; it does not guarantee every older or future client build.
- XHTTP is emitted for Mihomo but intentionally omitted from sing-box JSON in this project.

For release qualification, repeat the opt-in test with the release-bundled core versions and perform one live-node smoke test per supported transport.
