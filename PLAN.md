# Svault — MVP Plan

## Goal

A working local encrypted vault you can commit to git safely.
Nothing fancy. Just: init → add secret → get secret → it works.

## MVP Steps

### Step 1 — Encrypted vault (local, no daemon)
- [ ] `svault init` — generate age keypair, store private key protected by passphrase, create empty `vault.age`
- [ ] `svault secret add <NAME>` — prompt for value, encrypt and append to vault
- [ ] `svault secret get <NAME>` — prompt for passphrase, decrypt vault, return value
- [ ] `svault secret list` — list secret names only (never values)
- [ ] Vault file (`vault.age`) is safe to commit — encrypted at rest

### Step 2 — Policy file
- [ ] `svault.policy.yaml` — define callers, scopes, tiers
- [ ] `svault get <NAME> --scope X --reason "..."` — structured request, validated against policy

### Step 3 — Daemon + unlock
- [ ] `svault unlock` — decrypt vault into memory, start local socket
- [ ] `svault lock` — clear memory, stop socket
- [ ] Daemon handles requests so passphrase only needed once per session

### Step 4 — MCP tool
- [ ] `svault mcp` — start MCP server exposing `svault_get_secret`
- [ ] `svault install` — write MCP config to `.claude/settings.json`

## What's NOT in MVP

- Cloud tier / Claude scoring
- Team dashboard
- External backends (Vaultwarden, Infisical, etc.)
- Touch ID / YubiKey
- Binary distribution / install script

## Stack

- Python 3.11+
- `typer` — CLI framework
- `rich` — terminal output (tables, colours, prompts)
- `cryptography` — age-compatible encryption (Fernet or X25519+ChaCha20)
- `pyyaml` — policy file parsing
- `uv` — package management

## Run locally

```bash
uv sync
uv run svault version
```
