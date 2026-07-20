# VSA Design

## Purpose

A VSA (Verification Summary Attestation) is a cryptographically signed record that a specific
image was validated against a specific policy at a specific time. It enables skipping
re-validation when the same image+policy combination has already been verified and the VSA
hasn't expired.

## Why Multiple Storage Backends

VSAs can be stored locally (filesystem) or in Rekor (transparency log). Local storage is for
development and testing. Rekor storage provides tamper-evident public auditability — once a
VSA is logged, it can't be silently modified or deleted. The backend is selected at the CLI
level; the core logic is backend-agnostic via the storage interfaces in `storage.go`.

## DSSE Signing

VSAs are wrapped in DSSE (Dead Simple Signing Envelope) with signature verification enabled
by default. This was a deliberate security decision — unsigned VSAs would allow an attacker
to forge validation results and skip policy enforcement. The signing key is the same key used
for the original image validation.

## Expiration

VSAs have configurable expiration. This ensures that policy changes eventually take effect
even for previously-validated images. When a VSA is expired, the image must be re-validated
against the current policy. The threshold is set by the caller (typically 24h in production).
