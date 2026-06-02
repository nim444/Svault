#!/usr/bin/env bash
#
# qa-gate.sh — guided QA for the agent gate (checklist sections C, D, and the
# seal detection in E). Run it in YOUR terminal: you answer the few interactive
# setup prompts (master passphrase, secret values), and the script auto-asserts
# the deterministic gate behaviors and prints PASS/FAIL.
#
# It runs against an ISOLATED scratch store so it never touches your real
# ~/.svault. The interactive TUI/onboarding/YubiKey/MCP-client scenarios
# (sections A, B2, E5, F, H) are hands-on — this does not cover them.
#
# Usage:
#   ./scripts/qa-gate.sh [path-to-svault-binary]
# Default binary: target/release/svault (build it first with --features yubikey).

set -u

SV="${1:-$(dirname "$0")/../target/release/svault}"
export SVAULT_HOME="${SVAULT_HOME:-/tmp/svault-qa-gate}"

if [[ "$SVAULT_HOME" == "$HOME" || "$SVAULT_HOME" == "$HOME/" ]]; then
  echo "refusing to run against your home store ($HOME). Set SVAULT_HOME to a scratch dir." >&2
  exit 1
fi

pass=0; fail=0
ok()   { printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$1"; fail=$((fail+1)); }
head() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# assert_deny "<label>" <cmd...>  — expects non-zero exit AND the generic message.
assert_deny() {
  local label="$1"; shift
  local out; out="$("$@" 2>&1)"; local rc=$?
  if [[ $rc -ne 0 ]] && grep -q "not authorized for this secret" <<<"$out"; then
    ok "$label"
  else
    bad "$label (rc=$rc) :: $(tr '\n' ' ' <<<"$out" | head -c 160)"
  fi
}
# assert_allow "<label>" <cmd...> — expects zero exit and a value on stdout.
assert_allow() {
  local label="$1"; shift
  local out; out="$("$@" 2>/dev/null)"; local rc=$?
  if [[ $rc -eq 0 && -n "$out" ]]; then ok "$label"; else bad "$label (rc=$rc, empty=$([[ -z $out ]] && echo yes))"; fi
}

echo "binary:      $SV"
echo "SVAULT_HOME: $SVAULT_HOME"
"$SV" --version || { echo "binary not found — build it first" >&2; exit 1; }

rm -rf "$SVAULT_HOME/.svault"

cat <<'EOF'

──────────────────────────────────────────────────────────────────────────────
INTERACTIVE SETUP — answer the prompts (master passphrase once, secret values).
Accept the defaults on `create`. This builds the test vault the asserts need.
──────────────────────────────────────────────────────────────────────────────
EOF

head "1. Create vault 'qa' (sets the master on first run; SAVE the recovery code)"
"$SV" create --name qa || exit 1

head "2. Add tiered secrets (you'll be prompted for each value — any text is fine)"
"$SV" secret add DB_URL  --scope database --tier low    --description "dev dsn"        -v qa
"$SV" secret add API_KEY --scope api      --tier medium --description "billing key"    -v qa --require-caller ci
"$SV" secret add DEPLOY  --scope deploy   --tier high   --description "prod deploy key" -v qa

head "3. Start the daemon and unlock (so gets don't prompt)"
# NOTE: no `policy init`. The vault was created with "allow all agents", so it runs
# in FALLBACK mode — the gate still enforces reason/scope/tier/conditions, but any
# allowed agent may try. `policy init` would add named caller rules whose seeded
# scopes don't match these secrets (default holds none), which would deny the allow
# path below — that's the caller-scoped path, tested separately by hand.
"$SV" daemon start || true
"$SV" unlock -v qa || exit 1

# ── Automated assertions ────────────────────────────────────────────────────
head "C. The agent gate"
assert_allow "C1 allow path (DB_URL, good reason)" \
  "$SV" get DB_URL --scope database --reason "run the nightly database backup" --caller default -v qa
assert_deny  "C2 reason floor (too short)" \
  "$SV" get DB_URL --scope database --reason "need" --caller default -v qa
assert_deny  "C3 scope mismatch (database secret, api scope)" \
  "$SV" get DB_URL --scope api --reason "legit reason for the db read" --caller default -v qa
assert_deny  "C5 high-tier, no judge (DEPLOY denied to the agent)" \
  "$SV" get DEPLOY --scope deploy --reason "deploy the release tonight" --caller default -v qa

head "D. Conditional access"
assert_deny  "D1 required caller (API_KEY needs --caller ci, asked as 'claude')" \
  "$SV" get API_KEY --scope api --reason "charge the nightly invoices now" --caller claude -v qa
"$SV" secret add NOW_NO --scope ops --tier low --window "00:00-00:01" --require-caller ci -v qa
assert_deny  "D2 out-of-window (window 00:00-00:01, almost certainly closed now)" \
  "$SV" get NOW_NO --scope ops --reason "scheduled ops task run now" --caller ci -v qa

head "E. Seal & escalate (detection)"
for i in 1 2 3 4 5 6; do
  "$SV" get API_KEY --scope wrong --reason "probing scope number $i for testing" --caller ci -v qa >/dev/null 2>&1
done
if "$SV" pending -v qa 2>/dev/null | grep -q API_KEY; then
  ok "E1 sustained denials sealed API_KEY (listed by 'pending')"
else
  bad "E1 API_KEY did not seal after 6 denials"
fi
assert_deny "E2 sealed secret denies an otherwise-valid request" \
  "$SV" get API_KEY --scope api --reason "legitimate billing run for tonight" --caller ci -v qa

cat <<EOF

──────────────────────────────────────────────────────────────────────────────
HANDS-ON (not asserted here — do these yourself):
  E3  human still reads it:   $SV secret get API_KEY -v qa   (returns the value)
  E4  approve clears it:      $SV approve API_KEY -v qa      (RE-PROMPTS the master)
  E5  TUI approve (A key) · A onboarding · B2 classify form · F MCP client · H YubiKey
Cleanup:  $SV daemon stop ; rm -rf "$SVAULT_HOME/.svault"
──────────────────────────────────────────────────────────────────────────────

EOF

printf '\033[1mGate QA: %d passed, %d failed\033[0m\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
