# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue. Report vulnerabilities privately via
GitHub Security Advisories (`Security` → `Report a vulnerability`) or by e-mail to
<cumulus13@gmail.com>. You will receive a response within 7 days.

## Design notes

- Secrets come from the operating-system CSPRNG (`getrandom`).
- Secrets are held in memory that is zeroized on drop; `Debug` output is redacted.
- Code comparison is constant-time.
- Output files (`--qr-svg`) are created with mode `0600` on Unix and never overwritten without `--force`.
- `unsafe` code is forbidden in the library.
