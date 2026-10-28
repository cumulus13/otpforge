# otpforge

[![CI](https://github.com/cumulus13/otpforge/actions/workflows/ci.yml/badge.svg)](https://github.com/cumulus13/otpforge/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/otpforge.svg)](https://crates.io/crates/otpforge)
[![Docs.rs](https://docs.rs/otpforge/badge.svg)](https://docs.rs/otpforge)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Secure 2FA (TOTP) secret key generator for the command line — and a small Rust library.
Generates a secret, the `otpauth://` provisioning URI, a QR code (terminal or SVG), and single-use
backup codes. Also computes and verifies one-time codes (RFC 4226 / RFC 6238).

## Features

- **Authenticator mode**: save accounts once (`otpforge add pypi ...`), get login codes any time (`otpforge pypi`)
- Accepts the Base32 secret *or* the full `otpauth://` URI from a service's QR code
- Local vault with optional passphrase encryption (Argon2id + ChaCha20-Poly1305), atomic writes, mode `0600`
- Secret generator: OS CSPRNG, `otpauth://` URI, QR code (terminal or SVG), backup codes
- SHA-1 / SHA-256 / SHA-512, 6–8 digits, custom period; RFC 4226 / RFC 6238 test vectors
- Secrets zeroized on drop, redacted in `Debug`, constant-time code comparison, no `unsafe`
- Text or JSON output, shell completions, stable exit codes
- Windows, Linux, macOS, x86-64 / ARM64 (CI-tested), pure Rust

## Install

```sh
cargo install otpforge
```

Prebuilt binaries for every platform are attached to each [GitHub release](https://github.com/cumulus13/otpforge/releases).

## Quick start: use it as your authenticator (e.g. PyPI)

When a site shows its 2FA QR code, it also offers a text secret ("can't scan?"). Use either that secret
or the `otpauth://...` URI your QR reader gives you:

```sh
otpforge add pypi                       # prompts (hidden) for the secret or URI; prints the first code
otpforge add pypi 'otpauth://totp/PyPI:me?secret=ABCD...&issuer=PyPI'   # or pass it directly
otpforge pypi                           # login code (unique prefixes work: `otpforge py`)
otpforge pypi -c                        # ...and copy it to the clipboard
otpforge pypi | xclip -selection clipboard   # or pipe it (stdout is just the code; `| clip` on Windows, `| pbcopy` on macOS)
otpforge list --codes                   # all accounts with live codes
```

Every command is also available under the short alias `otp` (e.g. `otp pypi -c`). `-c/--copy` works with `NAME`,
`code` and `add` and uses `clip` (Windows), `pbcopy` (macOS) or `wl-copy` / `xclip` / `xsel` (Linux/BSD).

`add` prints the current code immediately, which is what the site asks for to finish enrolling.
Passing a secret as an argument leaves it in your shell history; prefer the prompt or `echo SECRET | otpforge add NAME`.

```sh
otpforge export pypi --qr               # re-show URI / QR to enrol another device
otpforge remove pypi                    # asks for confirmation (--yes to skip)
otpforge vault encrypt                  # protect the vault with a passphrase (prompted on use,
                                        # or set OTPFORGE_PASSPHRASE for scripts)
otpforge vault path                     # where the vault lives
```

The vault is stored in your config directory (`~/.config/otpforge/vault.json`,
`%APPDATA%\otpforge\vault.json`, `~/Library/Application Support/otpforge/vault.json`);
override with `--vault PATH` or `OTPFORGE_VAULT`. Without `vault encrypt` it is protected only by file
permissions, so encrypt it on shared or backed-up machines. **Back up your vault (and keep each
service's recovery codes): losing it means losing your codes.**

## Generate a new secret (you are the service, or you want a fresh key)

```sh
otpforge generate alice@example.com --issuer "ACME Co" --qr           # QR in the terminal
otpforge generate alice@example.com -i ACME --save acme               # also save it for `otpforge acme`
otpforge generate alice@example.com -i ACME --format json --qr-svg alice.svg --backup-codes 12
```

Use `--qr-light` if your terminal has a light background.

## Scripting

```sh
echo "JBSWY3DPEHPK3PXP" | otpforge code --secret-stdin -v         # one-off, nothing saved
otpforge verify pypi --code 123456 --window 1                     # exit 0 valid, 1 invalid, 2 error
OTPFORGE_SECRET=JBSWY3DPEHPK3PXP otpforge verify --code 123456
otpforge completions zsh > _otpforge
```

`sha1`, 6 digits and 30 s are the only settings every authenticator app supports.

| Exit code | Meaning                         |
|-----------|---------------------------------|
| 0         | Success / code valid            |
| 1         | Code invalid (`verify`)         |
| 2         | Usage or runtime error          |

## How it works

### Overview

```mermaid
flowchart LR
    user([You]) --> cli["otpforge / otp<br/>CLI"]

    cli -->|"add · list · remove · export"| vault
    cli -->|"NAME · code · verify"| vault
    cli -->|"generate --save"| vault
    cli -->|generate| gen["Secret + backup codes<br/>OS CSPRNG"]

    vault[("vault.json<br/>plaintext or encrypted")] --> totp["TOTP engine<br/>RFC 6238"]
    gen --> uri["otpauth:// URI"]
    uri --> qr["QR code<br/>terminal or SVG"]
    totp --> out["Code on stdout"]
    out --> clip["Clipboard with -c"]
    out --> pipe["Pipe to xclip, clip or pbcopy"]
```

[![Architecture 1](https://i.ibb.co/zDGqB92/architecture1.jpg)](https://i.ibb.co/zDGqB92/architecture1.jpg)


### Enrol once, log in any time

```mermaid
sequenceDiagram
    autonumber
    actor You
    participant App as otpforge
    participant Vault as vault.json
    participant Site as Service (e.g. PyPI)

    Site->>You: Shows QR code and text secret
    You->>App: otpforge add pypi (secret or otpauth URI)
    App->>App: Parse and validate
    App->>Vault: Save entry (atomic write, mode 0600)
    App-->>You: First code
    You->>Site: Enter code to finish enrolling

    Note over You,Site: Later, at login
    You->>App: otpforge pypi -c
    App->>Vault: Load (decrypt if encrypted)
    App-->>You: Current code, copied to clipboard
    You->>Site: Paste code
```

[![Architecture 2](https://i.ibb.co/p6zgQrdV/architecture2.jpg)](https://i.ibb.co/p6zgQrdV/architecture2.jpg)

### Vault encryption

```mermaid
flowchart TB
    subgraph save["Save an encrypted vault"]
        p1["Passphrase"] --> kdf1["Argon2id<br/>64 MiB, 3 passes, random 16-byte salt"]
        kdf1 --> key1["256-bit key"]
        entries["Accounts as JSON"] --> aead1["ChaCha20-Poly1305<br/>random 12-byte nonce"]
        key1 --> aead1
        aead1 --> file1["vault.json<br/>KDF header, nonce, ciphertext"]
    end

    subgraph load["Load an encrypted vault"]
        file2["vault.json"] --> chk["Check KDF limits"]
        p2["Passphrase<br/>prompt or OTPFORGE_PASSPHRASE"] --> kdf2["Argon2id"]
        chk --> kdf2
        kdf2 --> aead2["Decrypt and verify tag"]
        aead2 -->|ok| mem["Accounts in memory<br/>zeroized on drop"]
        aead2 -->|"tag mismatch"| fail["Error: wrong passphrase or corrupted vault"]
    end
```

[![Architecture 3](https://i.ibb.co/xtww12m5/architecture3.jpg)](https://i.ibb.co/xtww12m5/architecture3.jpg)

A fresh salt and nonce are generated on every save, and files are replaced atomically (temp file + rename).

### Library modules

```mermaid
flowchart BT
    cli["main.rs / bin/otp.rs<br/>CLI (clap)"] --> vault
    cli --> uri
    cli --> qr
    cli --> backup
    cli --> clipboard
    cli --> otp
    vault --> uri
    vault --> otp
    vault --> secret
    uri --> otp
    uri --> secret
    otp --> secret
```

[![Architecture 4](https://i.ibb.co/6JcnCgM8/architecture4.jpg)](https://i.ibb.co/6JcnCgM8/architecture4.jpg)

All modules share the `error` module.

### Release pipeline

```mermaid
flowchart LR
    tag["git tag vX.Y.Z"] --> verify["Tag must equal Cargo.toml version"]
    verify --> rel["Create GitHub release<br/>notes from CHANGELOG.md"]
    rel --> build

    subgraph build["Build matrix: otpforge + otp"]
        direction TB
        l1["Linux x86_64 gnu and musl"]
        l2["Linux aarch64 gnu"]
        m1["macOS x86_64 and aarch64"]
        w1["Windows x86_64, i686, aarch64"]
    end

    build --> assets["tar.gz / zip + SHA-256"]
    assets --> pub["cargo publish to crates.io"]
```

[![Architecture 5](https://i.ibb.co/m5mnX5r0/architecture5.jpg)](https://i.ibb.co/m5mnX5r0/architecture5.jpg)

## Library

```rust
use otpforge::{otp::{self, TotpParams}, secret::Secret, uri};

let secret = Secret::generate(20)?;
let params = TotpParams::default();
let provisioning = uri::totp_uri(&secret, "alice@example.com", Some("ACME"), &params)?;
let code = otp::totp(&secret, 1_700_000_000, &params)?;
assert_eq!(otp::verify(&secret, &code, 1_700_000_000, &params, 1)?, Some(0));
# Ok::<(), otpforge::Error>(())
```

## Security notes

- The generated secret and backup codes are printed to stdout; treat the terminal, logs and files accordingly.
- Prefer the interactive prompt, `--secret-stdin` or `OTPFORGE_SECRET` over passing secrets as arguments.
- Encrypted vaults use Argon2id (64 MiB, 3 passes) and ChaCha20-Poly1305 with a fresh salt and nonce on every save; a wrong passphrase and a tampered file are indistinguishable by design.
- Keeping password and 2FA codes on the same machine weakens 2FA; consider a separate device for high-value accounts.
- Store backup codes offline. See [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Minimum supported Rust version

Rust 1.85. MSRV bumps are treated as minor-version changes.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

Copyright © 2026 Hadi Cahyadi &lt;cumulus13@gmail.com&gt;


## 👤 Author
        
[Hadi Cahyadi](mailto:cumulus13@gmail.com)
    

[![Buy Me a Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/cumulus13)

[![Donate via Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/cumulus13)
 
[Support me on Patreon](https://www.patreon.com/cumulus13)
