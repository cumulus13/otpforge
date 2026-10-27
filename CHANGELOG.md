# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-28

### Added
- Authenticator mode: `add` (Base32 secret or `otpauth://` URI), `list`, `remove`, `export`, and the `otpforge NAME` shorthand for the current code.
- Local vault with optional passphrase encryption (`vault encrypt` / `vault decrypt` / `vault path`), `--vault` / `OTPFORGE_VAULT`.
- `generate --save NAME` stores the new account in the vault.
- `generate`: CSPRNG-backed 2FA secret, `otpauth://` URI, terminal/SVG QR code, backup codes, text or JSON output.
- `code`: print the current TOTP code for a secret.
- `verify`: verify a TOTP code with configurable drift window (exit status 0/1/2).
- `completions`: shell completion scripts (bash, zsh, fish, elvish, PowerShell).
- SHA-1, SHA-256 and SHA-512 support, 6–8 digits, configurable period.
- Library API (`secret`, `otp`, `uri`, `backup`, `qr`) with RFC 4226 / RFC 6238 test vectors.

[Unreleased]: https://github.com/cumulus13/otpforge/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cumulus13/otpforge/releases/tag/v0.1.0
