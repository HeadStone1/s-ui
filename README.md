# HeadStone1/s-ui Security Hardened Edition

<p align="center">
  <a href="./README.md">English EN</a> /
  <a href="./README.zh-CN.md">简体中文 CN</a>
</p>

`HeadStone1/s-ui` is a security-hardened maintenance fork of S-UI. It keeps the original Sing-Box Web panel functionality while improving the default deployment security and reducing risks for public-facing installations.

According to the original README, this repository is forked from the `alireza0/s-ui` v1.4.1 backup.

- Original project: <https://github.com/alireza0/s-ui>
- Current repository: <https://github.com/HeadStone1/s-ui>

## License and Disclaimer

This project follows the GNU General Public License v3.0. See [LICENSE](./LICENSE) for details.

This project is provided only for LAN-based learning, research, and technical exchange. Do not use it for illegal purposes. Users are responsible for complying with local laws and regulations.

## Security Hardening

### Accounts and Passwords

- Removed the default `admin/admin` administrator credential.
- The first startup generates a random administrator password.
- The administrator reset command no longer resets credentials to `admin/admin`.
- `admin/admin` is rejected as an administrator credential.
- Administrator passwords are stored with bcrypt hashes instead of plaintext.
- Login verification uses password hash comparison.
- The administrator info command no longer prints the real password.

### Web Session

- Session cookies use `HttpOnly`.
- Session cookies use `SameSite=Lax`.
- `Secure` cookies are enabled in HTTPS environments.
- A CSRF token is generated after login.
- Cookie-authenticated write requests require `X-CSRF-Token`.
- The frontend automatically attaches the CSRF token to protected requests.

### SQL Injection Fixes

- Fixed SQL string concatenation in change-query logic.
- `CheckChanges` parses numeric input and uses parameterized queries.
- `GetChanges` uses GORM parameter binding.
- Query count limits were added to avoid abnormally large requests.

### Login Brute-Force Protection

- Failed logins are limited by username and remote IP.
- Repeated failures trigger a temporary lockout.
- Client-provided `X-Forwarded-For` is not trusted by default.

### API Tokens

- API tokens are no longer stored in plaintext.
- Only token hashes are stored in the database.
- Token comparison uses a constant-time comparison.
- Tokens support `read`, `write`, and `admin` scopes.
- Tokens support expiration.
- High-risk operations require the `admin` scope.

### Database Import and Export

- Web database export now requires POST confirmation.
- Web database import and export require re-entering the current administrator password.
- Database upload size is limited.
- SQLite file headers are checked before import.
- A backup is created before import.
- API tokens are cleared and the session secret is regenerated after a successful import.

### SSRF Protection for External Links

- Only `http` and `https` are allowed.
- Localhost, private networks, link-local addresses, and unspecified addresses are blocked.
- Target IPs are checked after DNS resolution.
- Redirect targets are checked again.
- Request timeout and response body size limits are enforced.
- Non-HTTP protocols such as `file://`, `ftp://`, and `gopher://` are blocked.

### Subscription Links

- Subscription links no longer rely only on client names.
- Each client has an independent `sub_secret`.
- Subscription URLs use the client ID and a random secret.
- Old name-only subscription paths no longer return subscription content.

### Docker and Install Sources

- The default Docker Compose configuration no longer uses host networking.
- The Docker image runs as the non-root `sui` user.
- Compose enables `read_only: true`.
- `/tmp` uses tmpfs.
- The image path is now `ghcr.io/headstone1/s-ui`.
- Install scripts, update scripts, and release download URLs now point to `HeadStone1/s-ui`.
- The Go module and internal import paths now use `github.com/HeadStone1/s-ui`.
- Release archives are verified with sha256 checksums.
- The documentation no longer recommends `bash <(curl ...)`.

## Deployment

```sh
curl -fL -o install.sh https://raw.githubusercontent.com/HeadStone1/s-ui/main/install.sh
bash install.sh
```

After installation, save the random administrator password printed in the terminal and change it to a strong password as soon as possible.

## Deployment Recommendations

- Do not expose the management panel directly to the public internet without protection.
- Enable HTTPS.
- Place the panel behind a trusted reverse proxy.
- Restrict access to the management entry point.
- Use a strong administrator password.
- Rotate API tokens regularly.
- Back up and protect the database file.
- Keep images, binaries, and dependencies updated.

## Verification Status

The current version has passed the following basic checks:

```sh
gofmt
go test ./...
git diff --check
```

The Go backend compiles successfully, and no `admin8800` references remain in the repository.
