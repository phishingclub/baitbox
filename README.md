# Bait Box

[![Latest Release](https://img.shields.io/github/v/release/phishingclub/baitbox)](https://github.com/phishingclub/baitbox/releases/latest)
[![Discord](https://img.shields.io/badge/Discord-Join%20Server-7289da?style=flat&logo=discord&logoColor=white)](https://discord.gg/Zssps7U8gX)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Bait Box** is a self hosted content registry for Phishing Club.

## Quick start (production)

For systemd distributions, run the following on the server:

```
curl -fsSL https://raw.githubusercontent.com/phishingclub/baitbox/main/install.sh | bash
```

Remember to copy the admin URL, username and password. They are only printed once and are not saved to a file.

[GHCR Images](https://github.com/phishingclub/baitbox/pkgs/container/baitbox)

[Production Docker Compose example](https://github.com/phishingclub/baitbox/blob/main/docker-compose.production.yml). In a container the one time credentials are in `docker compose logs baitbox`.

## Features

- **Self hostable registry** - Run your own instance; Bait Box ships no content, you own what you publish
- **Namespaces and visibility** - Organize packages under namespaces; with a public registry each can be public or private
- **Variable system** - `@@VAR@@` tokens substituted at install time
- **Editors** - Write, preview and publish every Phishing Club content type, bundles included, in the admin UI
- **Export and import** - Move namespaces and packages to another registry as one file
- **In-app updates** - Signed updates from the admin UI
- **Operator security** - Optional two factor login and passkey support

## Ports

- `registry.address` (`:443`) - the registry that Phishing Club installs from
- `administration.address` (`:8443`) - the admin UI; restrict it with a firewall or `ip_security.admin_allowed`

Admin access can be turned off in Settings › Registry. Turn it back on with `baitbox -enable-admin` on the server.

The registry is private by default: every request needs a read token. Set `registry.public` to `true` to allow anonymous reads of public namespaces, and put a CDN or reverse proxy in front of a public registry.

## CLI

```
baitbox -config config.json      # serve
baitbox -install                 # install as a systemd service, interactive (root)
baitbox -install-non-interactive # install with a config template to edit (root)
baitbox -reinstall               # overwrite binary, unit and config after typing
                                  # YES; asks again, keeps all data (root)
baitbox -config-only -config c.json  # ask the questions, write the config only
baitbox -update                  # signed self update: fetch latest release,
                                  # verify ed25519 against the embedded keys,
                                  # refuse a downgrade, swap, restart
baitbox -uninstall               # remove service, data, user
baitbox -reset-admin             # reset the first operator's password, print new creds
                                  # (-username NAME picks another operator)
baitbox -reset-mfa NAME          # recovery: turn off two factor, delete every passkey
                                  # and sign out operator NAME; the password is kept
                                  # and the reset is logged
baitbox -disable-admin           # turn the admin UI and API off (sets administration.disabled)
baitbox -enable-admin            # turn the admin UI and API back on
```

Releases are built and signed by CI (`.github/workflows/release.yml`) for linux amd64 and arm64 on a semver tag. The private key is held only as the `SIGNKEY_1` repo secret; the public half is embedded at `embedded/signingkeys/public1.bin` (with `public2.bin` as a backup for rotation).

## Development

The production binary is a single static musl cgo build, produced with Docker so no host Go toolchain is needed:

```bash
make build            # build/baitbox for linux amd64
make build-arm        # build/baitbox for linux arm64 (needs qemu)
```

During development Bait Box runs in the dev Docker Compose stack as the `baitbox` service, with the registry listener on port 8112 and the admin listener on port 8114; compose rebuilds on change, so do not build manually for local work.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). This means:
- You can use, modify, and distribute the software
- If you provide the software modified as a network service, you must make your source code available under AGPL-3.0

## Support

Need help? Join the [Phishing Club Discord](https://discord.gg/Zssps7U8gX).

Community support is provided on a best effort, volunteer basis. For dedicated assistance, paid support is available.

- **General Support**: Join our Discord community or open a GitHub issue
- **Security Issues**: See our [Security Policy](SECURITY.md)

## Security and Ethical Use

This platform is designed for **authorized security testing only**.

For important information about reporting security vulnerabilities, ethical use requirements, legal responsibilities and security best practices, please read our [Security Policy](SECURITY.md).

**Important**: Users are solely responsible for ensuring their use complies with all applicable laws and regulations.
