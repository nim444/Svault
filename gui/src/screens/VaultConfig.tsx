import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createVault,
  judgeNames,
  saveSettings,
  vaultSettings,
  VaultForm,
} from "../lib/api";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useJudgeActive } from "../lib/hooks";
import { Page } from "../components/shell";
import {
  Button,
  Card,
  Checkbox,
  Field,
  Input,
  Modal,
  Segmented,
  Select,
  Toggle,
} from "../components/ui";

const emptyForm: VaultForm = {
  name: "",
  description: "",
  allow_agent_mode: "none",
  allow_agent_list: [],
  rate_limit: "10/hour",
  autolock: true,
  autolock_timer: "1d",
  login_method: "passphrase",
  default_tier: "low",
  judge_enabled: false,
  assigned_judge: null,
};

// Screen 04 — vault config. Create (/vaults/new) is a three-step wizard;
// edit (/vaults/:leaf/settings) is the flat form. Both write the same field
// set into the encrypted policy.
export default function VaultConfig() {
  const { leaf } = useParams();
  return leaf ? <EditForm leaf={leaf} /> : <CreateWizard />;
}

// Shared form helpers ─────────────────────────────────────────────────────────

function useVaultForm(initial: VaultForm) {
  const [form, setForm] = useState<VaultForm>(initial);
  const [callersText, setCallersText] = useState(
    initial.allow_agent_list.join(", "),
  );
  function set<K extends keyof VaultForm>(key: K, value: VaultForm[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }
  const finalForm = (): VaultForm => ({
    ...form,
    allow_agent_list:
      form.allow_agent_mode === "list"
        ? callersText
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : [],
    assigned_judge: form.judge_enabled ? form.assigned_judge || null : null,
  });
  return { form, set, setForm, callersText, setCallersText, finalForm };
}

function Explainer({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border-subtle bg-surface-sunken p-3 text-xs text-content-muted">
      {children}
    </div>
  );
}

const AGENT_MODE_HELP: Record<VaultForm["allow_agent_mode"], string> = {
  none: "No agent may request secrets from this vault — human-only access via the app, CLI, or TUI.",
  list: "Only the callers you name below may ask. Anything else is denied before any other check runs.",
  all: "Any caller may ask — every request still passes the full gate (scope, tier, rate limit, judge).",
};

// ── Create wizard ────────────────────────────────────────────────────────────

function CreateWizard() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const judgeActive = useJudgeActive();
  const judges = useQuery({ queryKey: ["judge-names"], queryFn: judgeNames });
  const { form, set, callersText, setCallersText, finalForm } =
    useVaultForm(emptyForm);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);

  const createM = useMutation({
    mutationFn: () => createVault(finalForm()),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["vaults"] });
      setRecoveryCode(res.recovery_code);
    },
    onError: (e) => setError(String(e)),
  });

  const steps = ["Basics", "Agent access", "Protection"];

  return (
    <Page title="Create vault">
      <Card className="mx-auto w-full max-w-xl p-6">
        {/* Step indicator */}
        <div className="mb-5 flex items-center gap-2 text-xs">
          {steps.map((s, i) => (
            <div key={s} className="flex items-center gap-2">
              {i > 0 && <span className="text-content-muted">—</span>}
              <span
                className={`flex items-center gap-1.5 ${
                  i === step ? "font-semibold text-content" : "text-content-muted"
                }`}
              >
                <span
                  className={`flex size-4.5 items-center justify-center rounded-full border text-[10px] ${
                    i < step
                      ? "border-state-allow/50 text-state-allow"
                      : i === step
                        ? "border-content"
                        : "border-border-subtle"
                  }`}
                >
                  {i < step ? "✓" : i + 1}
                </span>
                {s}
              </span>
            </div>
          ))}
        </div>

        {step === 0 && (
          <div className="flex flex-col gap-4">
            <Explainer>
              A vault is one encrypted store for one project's secrets — its
              own policy, its own audit trail, unlocked by your master
              passphrase. Everything you set here is stored encrypted.
            </Explainer>
            <Field
              label="Name"
              hint="Unique on this machine; doubles as the vault's id (e.g. billing-api)."
            >
              <Input
                autoFocus
                value={form.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="my-project"
              />
            </Field>
            <Field
              label="Description"
              hint="The vault's stated purpose. The AI judge reads it with every request — 'production billing service' makes it rightly suspicious of odd reasons; blank tells it nothing."
            >
              <Input
                value={form.description}
                onChange={(e) => set("description", e.target.value)}
                placeholder="e.g. production billing service"
              />
            </Field>
            <div className="flex justify-end gap-2 border-t border-border-subtle pt-4">
              <Button variant="ghost" onClick={() => navigate("/vaults")}>
                Cancel
              </Button>
              <Button disabled={!form.name.trim()} onClick={() => setStep(1)}>
                Next
              </Button>
            </div>
          </div>
        )}

        {step === 1 && (
          <div className="flex flex-col gap-4">
            <Explainer>
              Agents reach secrets through the gate (MCP). Here you decide who
              may even ask — every allowed request still runs the full check:
              scope, tier, rate limit, and the judge's verdict on the reason.
            </Explainer>
            <Field label="Who may ask">
              <div className="flex flex-col gap-2">
                <Segmented
                  value={form.allow_agent_mode}
                  onChange={(v) => set("allow_agent_mode", v)}
                  options={[
                    { value: "none", label: "No agents" },
                    { value: "list", label: "Named only" },
                    { value: "all", label: "Any agent" },
                  ]}
                />
                <p className="text-xs text-content-muted">
                  {AGENT_MODE_HELP[form.allow_agent_mode]}
                </p>
                {form.allow_agent_mode === "list" && (
                  <Input
                    placeholder="caller names, comma-separated (e.g. claude-code, opencode)"
                    value={callersText}
                    onChange={(e) => setCallersText(e.target.value)}
                  />
                )}
              </div>
            </Field>
            <Field
              label="Rate limit"
              hint="Caps how fast any one caller can pull secrets — e.g. 10/hour or 100/day. A runaway agent hits the ceiling instead of draining the vault."
            >
              <Input
                className="w-40"
                value={form.rate_limit}
                onChange={(e) => set("rate_limit", e.target.value)}
                placeholder="10/hour"
              />
            </Field>
            <div className="flex justify-between gap-2 border-t border-border-subtle pt-4">
              <Button variant="ghost" onClick={() => setStep(0)}>
                Back
              </Button>
              <Button onClick={() => setStep(2)}>Next</Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="flex flex-col gap-4">
            <Explainer>
              Each secret gets a sensitivity tier (you can override per secret
              later): <strong>low</strong> is released on request,{" "}
              <strong>medium</strong> needs the AI judge to accept the reason,{" "}
              <strong>high</strong> is judged strictly
              {judgeActive ? "" : " — and human-only while no judge is active"}
              . New secrets start at the default you pick here.
            </Explainer>
            <Field label="Default tier">
              <Segmented
                value={form.default_tier}
                onChange={(v) => set("default_tier", v)}
                options={[
                  { value: "low", label: "Low" },
                  { value: "medium", label: "Medium" },
                  { value: "high", label: "High" },
                ]}
              />
            </Field>

            {judgeActive && (
              <Field label="AI judge">
                <div className="flex flex-col gap-2">
                  <Checkbox
                    checked={form.judge_enabled}
                    onChange={(v) => set("judge_enabled", v)}
                  >
                    Use the AI judge for this vault's medium/high secrets
                  </Checkbox>
                  {form.judge_enabled && (
                    <Select
                      className="w-64"
                      value={form.assigned_judge ?? ""}
                      onChange={(e) => set("assigned_judge", e.target.value || null)}
                    >
                      <option value="">default judge</option>
                      {(judges.data ?? []).map((j) => (
                        <option key={j} value={j}>
                          {j}
                        </option>
                      ))}
                    </Select>
                  )}
                </div>
              </Field>
            )}

            <Field
              label="Auto-lock"
              hint="Re-locks the vault after this long without use; unlocking again takes your passphrase (or YubiKey)."
            >
              <div className="flex items-center gap-4">
                <Toggle
                  checked={form.autolock}
                  onChange={(v) => set("autolock", v)}
                  label="Lock when idle"
                />
                {form.autolock && (
                  <Select
                    className="w-32"
                    value={form.autolock_timer}
                    onChange={(e) => set("autolock_timer", e.target.value)}
                  >
                    <option value="30m">30m</option>
                    <option value="12h">12h</option>
                    <option value="1d">1d</option>
                  </Select>
                )}
              </div>
            </Field>

            <Field
              label="Unlock with"
              hint="How a human opens this vault. YubiKey needs a key enrolled in Settings."
            >
              <Select
                className="w-48"
                value={form.login_method}
                onChange={(e) =>
                  set("login_method", e.target.value as VaultForm["login_method"])
                }
              >
                <option value="passphrase">Passphrase</option>
                <option value="yubikey">YubiKey</option>
              </Select>
            </Field>

            {error && <p className="text-sm text-state-deny">{error}</p>}
            <div className="flex justify-between gap-2 border-t border-border-subtle pt-4">
              <Button variant="ghost" onClick={() => setStep(1)}>
                Back
              </Button>
              <Button onClick={() => createM.mutate()} disabled={createM.isPending}>
                {createM.isPending ? "Creating…" : "Create vault"}
              </Button>
            </div>
          </div>
        )}
      </Card>

      {recoveryCode && (
        <RecoveryModal code={recoveryCode} onDone={() => navigate("/vaults")} />
      )}
    </Page>
  );
}

// ── Edit form ────────────────────────────────────────────────────────────────

function EditForm({ leaf }: { leaf: string }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const judgeActive = useJudgeActive();
  const judges = useQuery({ queryKey: ["judge-names"], queryFn: judgeNames });
  const { form, set, setForm, callersText, setCallersText, finalForm } =
    useVaultForm(emptyForm);
  const [error, setError] = useState<string | null>(null);

  const existing = useQuery({
    queryKey: ["vault-settings", leaf],
    queryFn: () => vaultSettings(leaf),
  });

  useEffect(() => {
    if (existing.data) {
      const { leaf: _leaf, ...rest } = existing.data;
      setForm(rest);
      setCallersText(rest.allow_agent_list.join(", "));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [existing.data]);

  const saveM = useMutation({
    mutationFn: () => saveSettings(leaf, finalForm()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vaults"] });
      navigate("/vaults");
    },
    onError: (e) => setError(String(e)),
  });

  return (
    <Page title={`Edit settings · ${form.name}`}>
      <Card className="max-w-2xl p-6">
        <div className="flex flex-col gap-5">
          <Field
            label="Description"
            hint="The vault's stated purpose — the AI judge reads it with every request."
          >
            <Input
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
            />
          </Field>

          <Field label="Who may ask" hint="Which agent callers may request secrets via the gate.">
            <div className="flex flex-col gap-2">
              <Segmented
                value={form.allow_agent_mode}
                onChange={(v) => set("allow_agent_mode", v)}
                options={[
                  { value: "none", label: "No agents" },
                  { value: "list", label: "Named only" },
                  { value: "all", label: "Any agent" },
                ]}
              />
              <p className="text-xs text-content-muted">
                {AGENT_MODE_HELP[form.allow_agent_mode]}
              </p>
              {form.allow_agent_mode === "list" && (
                <Input
                  placeholder="caller names, comma-separated"
                  value={callersText}
                  onChange={(e) => setCallersText(e.target.value)}
                />
              )}
            </div>
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field
              label="Rate limit"
              hint="Caps how fast any one caller can pull secrets, e.g. 10/hour."
            >
              <Input
                value={form.rate_limit}
                onChange={(e) => set("rate_limit", e.target.value)}
                placeholder="10/hour"
              />
            </Field>
            <Field
              label="Default tier"
              hint={
                judgeActive
                  ? "low released on request · medium judge-gated · high judged strictly."
                  : "medium/high are human-only until an AI judge is active."
              }
            >
              <Segmented
                value={form.default_tier}
                onChange={(v) => set("default_tier", v)}
                options={[
                  { value: "low", label: "Low" },
                  { value: "medium", label: "Medium" },
                  { value: "high", label: "High" },
                ]}
              />
            </Field>
          </div>

          <Field
            label="Auto-lock"
            hint="Re-locks the vault after this long without use."
          >
            <div className="flex items-center gap-4">
              <Toggle
                checked={form.autolock}
                onChange={(v) => set("autolock", v)}
                label="Lock when idle"
              />
              {form.autolock && (
                <Select
                  className="w-32"
                  value={form.autolock_timer}
                  onChange={(e) => set("autolock_timer", e.target.value)}
                >
                  <option value="30m">30m</option>
                  <option value="12h">12h</option>
                  <option value="1d">1d</option>
                </Select>
              )}
            </div>
          </Field>

          <Field label="Unlock with" hint="How a human opens this vault.">
            <Select
              className="w-48"
              value={form.login_method}
              onChange={(e) =>
                set("login_method", e.target.value as VaultForm["login_method"])
              }
            >
              <option value="passphrase">Passphrase</option>
              <option value="yubikey">YubiKey</option>
            </Select>
          </Field>

          {judgeActive && (
            <Field label="AI judge">
              <div className="flex flex-col gap-2">
                <Checkbox
                  checked={form.judge_enabled}
                  onChange={(v) => set("judge_enabled", v)}
                >
                  Use the AI judge for this vault's medium/high secrets
                </Checkbox>
                {form.judge_enabled && (
                  <Select
                    className="w-64"
                    value={form.assigned_judge ?? ""}
                    onChange={(e) => set("assigned_judge", e.target.value || null)}
                  >
                    <option value="">default judge</option>
                    {(judges.data ?? []).map((j) => (
                      <option key={j} value={j}>
                        {j}
                      </option>
                    ))}
                  </Select>
                )}
              </div>
            </Field>
          )}

          {error && <p className="text-sm text-state-deny">{error}</p>}

          <div className="flex justify-end gap-2 border-t border-border-subtle pt-4">
            <Button variant="secondary" onClick={() => navigate("/vaults")}>
              Cancel
            </Button>
            <Button onClick={() => saveM.mutate()} disabled={saveM.isPending}>
              {saveM.isPending ? "Saving…" : "Save changes"}
            </Button>
          </div>
        </div>
      </Card>
    </Page>
  );
}

// Matches the approved onboarding recovery UX: red warning, green code box,
// bold confirm checkbox, Done fully dimmed until checked.
function RecoveryModal({ code, onDone }: { code: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <Modal title="Vault recovery code" onClose={() => {}}>
      <p className="text-sm text-state-deny">
        Shown once, never stored in plaintext. It re-attaches this vault if you
        lose your master passphrase. Save it now.
      </p>
      <div className="my-4 rounded-lg border border-state-allow/40 bg-state-allow/10 p-3 text-center font-mono text-sm tracking-wide">
        {code}
      </div>
      <Button
        variant="secondary"
        className="mb-4 w-full"
        onClick={async () => {
          await writeText(code);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      <Checkbox checked={saved} onChange={setSaved}>
        <span className="font-semibold">I've stored this somewhere safe</span>
      </Checkbox>
      <div className="mt-5 flex justify-end">
        <Button
          disabled={!saved}
          className="disabled:bg-muted disabled:text-muted-foreground disabled:opacity-100"
          onClick={onDone}
        >
          Done
        </Button>
      </div>
    </Modal>
  );
}
