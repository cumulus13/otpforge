# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.10] - 2026-10-29

### Fixed
- Clipboard: a tool that exits before reading its input no longer causes a spurious "Broken pipe" error (flaky test on ARM runners).
- CI: MSRV job pins Rust 1.85.0 through the `toolchain` input so Dependabot cannot rewrite it into a non-existent toolchain.

## [0.1.9] - 2026-10-28

### Added
- Android / Termux support: prebuilt release archives for `aarch64-linux-android` (arm64-v8a), `armv7-linux-androideabi` (armeabi-v7a, Termux `armv7l`/`armv8l`), `x86_64-linux-android` and `i686-linux-android`, built against Android API 24+.
- CI job that cross-builds and test-compiles all four Android targets with the NDK.
- `-c` / `--copy` uses `termux-clipboard-set` on Android (`pkg install termux-api`).

## [0.1.8] - 2026-10-28

### Added
- `-c` / `--copy` copies the code to the clipboard (`otpforge NAME -c`, `code -c`, `add -c`); piping the plain code to `xclip`, `clip` or `pbcopy` also works.
- `otp` binary as a short alias for `otpforge`.

- Mermaid diagrams in the README (overview, enrolment flow, vault encryption, modules, release pipeline).

### Changed
- `list --codes` no longer has the `-c` short flag (now used for `--copy`).

## [0.1.6] - 2026-10-28

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
