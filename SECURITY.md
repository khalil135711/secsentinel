# Security Policy

SecSentinel is a defensive, read-only analysis tool. It does not scan networks,
exploit anything or modify the systems it inspects.

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's
"Report a vulnerability" button (Security tab -> Advisories) on this repository
and include steps to reproduce. You can expect an initial reply within a week.

## Scope notes

- Passwords audited with `secsentinel passwords` are processed locally and are
  never written to disk or printed in clear text.
- Integrity baselines contain file paths and SHA-256 hashes. Protect the
  baseline file: an attacker who can rewrite it can hide changes.
