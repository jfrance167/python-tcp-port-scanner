# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational TCP scanner for systems the operator owns or
has explicit permission to test. It is not production software and does not
include an intentionally vulnerable target.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Do not place
credentials, tokens, private keys, packet captures, or other sensitive evidence
in a public issue. If a real credential is exposed, revoke and rotate it before
attempting repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, the documented test suite,
and GitHub secret scanning. Review generated output before adding it to Git.
