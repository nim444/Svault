# End-to-end walkthrough

A complete run-through of Svault's AI-aware flow: create a vault, classify secrets
with descriptions, define callers, turn on the AI judge, and watch a real model
grant or deny agent requests. The judge outputs below are **actual responses** from
`google/gemini-2.5-flash` via OpenRouter.

> **Vaults are addressed by name.** You can have several (local today, remote on the
> [roadmap](roadmap.md)), so every secret/get/settings command takes `-v <vault>`.
> Omit it only when there's a single vault.

## 1. Build

```bash
git clone https://github.com/Soluzy/Svault.git
cd Svault && cargo build --release
alias svault="$PWD/target/release/svault"
```

## 2. Create a vault (with a description)

```bash
svault create
#   Name:           billing-api
#   Description:    production billing service           ← the judge sees this
#   Allow agents:   list  → claude-code, billing-worker
#   Rate limit:     20/hour
#   Default tier:   medium
#   Use AI judge:   yes
#   Passphrase:     ********
# → prints a one-time RECOVERY CODE; save it.
```

The vault description is overall context for the judge. Storage is `local` today.

## 3. Add secrets — classify them and say what they're for

`--description` records the secret's purpose. The judge weighs each request's
*reason* against it, so an off-purpose request is denied.

```bash
svault secret add DATABASE_URL -v billing-api --scope database --tier medium \
  --description "production Postgres connection string"

svault secret add STRIPE_KEY -v billing-api --scope payments --tier high --require-reason \
  --description "production Stripe charge key — only for billing/charge flows"
```

Classification lives in the **HMAC-signed `meta.yaml`** — a same-UID process can't
downgrade a tier or rewrite a purpose without the vault key. In the TUI, `a` in the
secret browser opens the same form (name / value / scope / description / tier /
require-reason).

## 4. Define who may ask (callers)

```bash
svault policy init          # scaffold svault.policy.yaml (committable; no secrets)
$EDITOR svault.policy.yaml
```

```yaml
version: 1
callers:
  claude-code:
    scopes: [database, api]
    rate_limit: 20/hour
  billing-worker:
    scopes: [payments]
    rate_limit: 60/hour
  default:
    scopes: []
    rate_limit: 5/hour
```

```bash
svault policy check claude-code   # what it can reach + recent activity
```

## 5. Turn on the AI judge

The key never goes in config or the repo — it lives in `$SVAULT_OPENROUTER_KEY`
or a `0600` file under `~/.config/svault/`.

```bash
svault judge set-key        # paste the key (hidden); or: echo "$KEY" | svault judge set-key
svault judge status
# judge: enabled=false model=google/gemini-2.5-flash (allow≥60, high≥80) timeout=6s
#   key: present (~/.config/svault/openrouter.key)
```

Enable it in `.svault/config.yaml` (`judge.enabled: true`) or per vault at create.

## 6. Dry-run the model — `svault judge test`

This builds a sample request and asks the live model; nothing is read or written.
Pass a realistic `--vault` (the model sees it) and the descriptions. Real outputs:

```bash
# Plausible reason that matches the vault → ALLOW
svault judge test --vault billing-api --vault-description "production billing service" \
  --tier medium --scope database --secret DATABASE_URL \
  --reason "run the nightly billing migration against the production database" --caller claude-code
# ALLOW score 95 — Nightly billing migration is a plausible and specific reason for
#                  accessing the production database URL, matching the vault's purpose.

# Vague reason → DENY
svault judge test --vault billing-api --tier medium --scope database --secret DATABASE_URL \
  --reason "asdf" --caller claude-code
# DENY score 10 — Stated reason 'asdf' is vague and unspecific.

# Reason matches the secret's description → ALLOW
svault judge test --vault billing-api --tier high --scope payments --secret STRIPE_KEY \
  --description "production Stripe charge key — only for billing/charge flows" \
  --reason "charge a customer invoice for the monthly subscription" --caller billing-worker
# ALLOW score 95 — Caller is a billing worker, requesting a Stripe key for a billing-api
#                  vault to charge a customer invoice, which aligns perfectly with the
#                  secret's purpose.

# Reason contradicts the secret's description → DENY
svault judge test --vault billing-api --tier high --scope payments --secret STRIPE_KEY \
  --description "production Stripe charge key — only for billing/charge flows" \
  --reason "export the full customer email list for a marketing campaign" --caller billing-worker
# DENY score 90 — Stated reason does not match secret's purpose. STRIPE_KEY is for
#                 billing/charge flows, not exporting customer email lists.
```

The last two are the headline behaviour: same secret, same caller, same tier — the
**reason vs. the documented purpose** is what flips the decision.

## 7. The agent request — `svault get`

Unlock once (or run the [daemon](daemon.md) so the key stays in memory), then the
agent path runs the full gate: policy → tier → judge → audit, **enforced inside the
daemon**.

```bash
svault daemon start
svault unlock -v billing-api

# Granted — reason fits the secret's purpose
svault get STRIPE_KEY -v billing-api --scope payments \
  --reason "charge a customer invoice for the monthly subscription" --caller billing-worker
# → sk_live_...        (value to stdout; status + rationale to stderr)

# Denied — reason doesn't fit
svault get STRIPE_KEY -v billing-api --scope payments \
  --reason "export the customer email list for marketing" --caller billing-worker
# → error: judge denied (score 90) — reason does not match the secret's purpose
#   (exits non-zero; no value printed)
```

On allow, only the value goes to stdout, so an agent capturing stdout never sees the
rationale. On deny it exits non-zero.

## 8. Tiers and fail modes

| Tier | Judge on | If the judge is unreachable |
|---|---|---|
| `low` | skipped (unless `require_reason`) | allow |
| `medium` | allow if score ≥ `allow_threshold` (60) | **fail-open**, audit-flagged `judge-unavailable` |
| `high` | allow if score ≥ `high_threshold` (80) | **fail-closed** (deny) |

With the judge **off**, it falls back to the pre-0.9.0 rule (high = human-only), so
nothing regresses. Verify fail-closed by pointing `judge.base_url` at an unreachable
host and requesting a high-tier secret — it denies.

## 9. Review the audit trail

Every decision is appended to `.svault/billing-api/audit.log` (gitignored, `0600`),
stamped with the **peer UID** of the connecting process (unforgeable, unlike the
self-asserted `--caller`) and the judge's score + rationale — never the secret value.

```bash
svault policy check billing-worker   # scopes, reachable secrets, recent allows/denials
```

## Notes

- **Key safety.** The OpenRouter key is only ever in the env var or the `0600`
  key file outside the repo; `.gitignore` also blocks `*.key`. Rotate the key if it
  is ever exposed (e.g. pasted into a chat or log).
- **What the judge sees.** name, scope, tier, caller, reason, recent activity, and any
  vault/secret descriptions — **never the secret value**. Keep descriptions free of
  sensitive data, since they are sent to the model. See [security.md](security.md#ai-judge).
- **Honest boundary.** This enforces the gate for cooperative/semi-trusted agents and
  gives a tamper-resistant audit trail. It is *not* a sandbox against a hostile
  same-UID process, which can read the daemon's memory directly.
