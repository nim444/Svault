import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Eye, Pencil, Trash2 } from "lucide-react";
import {
  addSecret,
  editSecret,
  listSecrets,
  removeSecret,
  revealSecret,
  SecretForm,
  SecretSummary,
  vaultSettings,
} from "../lib/api";
import { useJudgeActive } from "../lib/hooks";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import {
  Badge,
  Button,
  Card,
  Checkbox,
  ConfirmDialog,
  Field,
  Input,
  Modal,
  TierBadge,
} from "../components/ui";

// Screen 05 — a vault's secrets. Card grid + a two-step add/edit wizard in a
// modal (Secret → Access rules), consistent with vaults/providers/judges.
export default function Secrets() {
  const { leaf } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const judgeActive = useJudgeActive();
  const [wizard, setWizard] = useState<SecretSummary | null | "new">(null);
  const [toDelete, setToDelete] = useState<SecretSummary | null>(null);
  const [revealed, setRevealed] = useState<{ name: string; value: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const meta = useQuery({
    queryKey: ["vault-settings", leaf],
    queryFn: () => vaultSettings(leaf!),
  });
  const secrets = useQuery({
    queryKey: ["secrets", leaf],
    queryFn: () => listSecrets(leaf!),
  });

  const refresh = () => qc.invalidateQueries({ queryKey: ["secrets", leaf] });

  const deleteM = useMutation({
    mutationFn: (name: string) => removeSecret(leaf!, name),
    onSuccess: () => {
      setToDelete(null);
      refresh();
    },
  });

  const revealM = useMutation({
    mutationFn: (name: string) => revealSecret(leaf!, name),
    onSuccess: (value, name) => setRevealed({ name, value }),
    onError: (e) => setError(String(e)),
  });

  const rows = secrets.data ?? [];

  return (
    <Page
      title={`Secrets · ${meta.data?.name ?? leaf}`}
      actions={
        <>
          <Button variant="secondary" onClick={() => navigate("/vaults")}>
            ← Vaults
          </Button>
          <Button onClick={() => setWizard("new")}>+ Add secret</Button>
        </>
      }
    >
      {secrets.isLoading && <p className="text-content-muted">Loading…</p>}
      {secrets.error && <p className="text-state-deny">{String(secrets.error)}</p>}
      {error && <p className="mb-3 text-sm text-state-deny">{error}</p>}

      {rows.length === 0 && !secrets.isLoading && (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          No secrets yet. Add the first one — it's stored AES-256-GCM encrypted
          and released only through the gate.
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {rows.map((s) => (
          <Card key={s.name} className="flex flex-col p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate font-mono text-sm font-medium">
                    {s.name}
                  </span>
                  <Badge tone="neutral">{s.scope || "misc"}</Badge>
                  <TierBadge tier={s.tier} />
                  {s.sealed && <Badge tone="deny">sealed</Badge>}
                  {s.require_reason && <Badge tone="judge">always judged</Badge>}
                </div>
                <p className="mt-1 truncate text-xs text-content-muted">
                  {s.description || "no description"}
                </p>
              </div>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-content-muted">
              <span>
                callers: {s.callers.length ? s.callers.join(", ") : "any"}
              </span>
              <span>·</span>
              <span>window: {s.windows.length ? s.windows.join("; ") : "any"}</span>
              <span className="ml-auto">read {shortTime(s.last_read)}</span>
            </div>

            <div className="mt-3 flex items-center gap-1 border-t border-border-subtle pt-3">
              <Button
                variant="secondary"
                className="gap-1.5 px-3 py-1 text-xs"
                onClick={() => revealM.mutate(s.name)}
              >
                <Eye className="size-3.5" />
                Reveal
              </Button>
              <Button
                variant="ghost"
                className="gap-1.5 px-2 py-1 text-xs"
                onClick={() => setWizard(s)}
              >
                <Pencil className="size-3.5" />
                Edit
              </Button>
              <Button
                variant="ghost"
                className="ml-auto px-2 py-1 text-xs text-state-deny"
                title="Delete secret"
                onClick={() => setToDelete(s)}
              >
                <Trash2 className="size-3.5" />
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {wizard !== null && (
        <SecretWizard
          leaf={leaf!}
          existing={wizard === "new" ? null : wizard}
          judgeActive={judgeActive}
          onClose={() => setWizard(null)}
          onSaved={() => {
            setWizard(null);
            refresh();
          }}
        />
      )}

      {toDelete && (
        <ConfirmDialog
          title={`Delete secret "${toDelete.name}"?`}
          danger
          confirmLabel="Delete secret"
          busy={deleteM.isPending}
          message={
            <>
              The value and its classification are destroyed.{" "}
              <strong>This cannot be undone</strong> — a vault export is the
              only way back.
            </>
          }
          onCancel={() => setToDelete(null)}
          onConfirm={() => deleteM.mutate(toDelete.name)}
        />
      )}

      {revealed && (
        <Modal title={`Value · ${revealed.name}`} onClose={() => setRevealed(null)}>
          <div className="rounded-lg border border-border-subtle bg-surface-sunken p-3 font-mono text-sm break-all">
            {revealed.value}
          </div>
          <p className="mt-2 text-xs text-content-muted">
            This read is recorded in the activity timeline.
          </p>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => writeText(revealed.value)}>
              Copy
            </Button>
            <Button onClick={() => setRevealed(null)}>Close</Button>
          </div>
        </Modal>
      )}
    </Page>
  );
}

// ── Add/edit wizard ──────────────────────────────────────────────────────────
// Two steps: the secret itself, then who gets it and when.

const TIERS: { value: SecretForm["tier"]; title: string; desc: string }[] = [
  {
    value: "low",
    title: "Low",
    desc: "Released on request. Non-sensitive values: public URLs, ids, feature flags.",
  },
  {
    value: "medium",
    title: "Medium",
    desc: "The AI judge must accept the caller's reason first. Good default for API keys.",
  },
  {
    value: "high",
    title: "High",
    desc: "Judged strictly; human-only while no judge is active. Production credentials.",
  },
];

function SecretWizard({
  leaf,
  existing,
  judgeActive,
  onClose,
  onSaved,
}: {
  leaf: string;
  existing: SecretSummary | null;
  judgeActive: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [step, setStep] = useState(0);
  const [name, setName] = useState(existing?.name ?? "");
  const [value, setValue] = useState("");
  const [scope, setScope] = useState(existing?.scope || "misc");
  const [tier, setTier] = useState<SecretForm["tier"]>(
    (existing?.tier as SecretForm["tier"]) || "low",
  );
  const [requireReason, setRequireReason] = useState(
    existing?.require_reason ?? false,
  );
  const [description, setDescription] = useState(existing?.description ?? "");
  const [callersText, setCallersText] = useState(existing?.callers.join(", ") ?? "");
  const [windowsText, setWindowsText] = useState(existing?.windows.join(", ") ?? "");
  const [error, setError] = useState<string | null>(null);

  const saveM = useMutation({
    mutationFn: () => {
      const form: SecretForm = {
        name: name.trim(),
        value: value || null,
        scope: scope.trim() || "misc",
        tier,
        require_reason: requireReason,
        description,
        windows: windowsText.split(",").map((s) => s.trim()).filter(Boolean),
        require_callers: callersText.split(",").map((s) => s.trim()).filter(Boolean),
      };
      return existing ? editSecret(leaf, form) : addSecret(leaf, form);
    },
    onSuccess: onSaved,
    onError: (e) => setError(String(e)),
  });

  const steps = ["Secret", "Access rules"];

  return (
    <Modal
      title={existing ? `Edit secret · ${existing.name}` : "Add secret"}
      onClose={onClose}
      width="max-w-lg"
    >
      <div className="mb-4 flex items-center gap-2 text-xs">
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
        <div className="flex flex-col gap-3">
          <Field
            label="Name"
            hint={
              existing
                ? "The name identifies the secret — it can't be changed."
                : "How callers ask for it — usually the env-var name (e.g. DATABASE_URL)."
            }
          >
            <Input
              autoFocus={!existing}
              className="font-mono"
              value={name}
              disabled={!!existing}
              placeholder="DATABASE_URL"
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <Field
            label="Value"
            hint="AES-256-GCM encrypted into vault.enc; never logged, shown only on explicit reveal."
          >
            <Input
              type="password"
              placeholder={existing ? "unchanged" : ""}
              value={value}
              onChange={(e) => setValue(e.target.value)}
            />
          </Field>
          <Field
            label="Scope"
            hint="The secret's category. A request must state the matching scope — an agent asking for 'database' never sees 'payments'."
          >
            <Input
              value={scope}
              placeholder="e.g. database, api, payments"
              onChange={(e) => setScope(e.target.value)}
            />
          </Field>
          <div className="flex justify-end gap-2 border-t border-border-subtle pt-4">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              disabled={!name.trim() || (!existing && !value)}
              onClick={() => setStep(1)}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {step === 1 && (
        <div className="flex flex-col gap-3">
          <Field label="Sensitivity tier">
            <div role="radiogroup" className="flex flex-col gap-2">
              {TIERS.map((t) => (
                <button
                  key={t.value}
                  type="button"
                  role="radio"
                  aria-checked={tier === t.value}
                  onClick={() => setTier(t.value)}
                  className={`flex items-start gap-3 rounded-lg border p-3 text-left transition-colors ${
                    tier === t.value
                      ? "border-primary bg-surface-raised"
                      : "border-border-subtle hover:bg-surface-raised/50"
                  }`}
                >
                  <span
                    className={`mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border ${
                      tier === t.value ? "border-primary" : "border-border-subtle"
                    }`}
                  >
                    {tier === t.value && (
                      <span className="size-2 rounded-full bg-primary" />
                    )}
                  </span>
                  <span>
                    <span className="block text-sm font-medium">{t.title}</span>
                    <span className="block text-xs text-content-muted">
                      {t.value !== "low" && !judgeActive
                        ? `${t.desc} No judge is active yet, so this is human-only for now.`
                        : t.desc}
                    </span>
                  </span>
                </button>
              ))}
            </div>
          </Field>

          {judgeActive && (
            <Checkbox checked={requireReason} onChange={setRequireReason}>
              Always ask the judge — even at low tier
            </Checkbox>
          )}

          <Field
            label="Description"
            hint="What this secret is for. The judge weighs it against each request's reason — 'production Postgres connection string' beats silence."
          >
            <Input
              value={description}
              placeholder="e.g. production Postgres connection string"
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          <Field
            label="Allowed callers"
            hint="Restrict to specific agent identities, comma-separated (e.g. claude-code, ci-bot). Blank = any caller the vault allows."
          >
            <Input
              value={callersText}
              placeholder="blank = any"
              onChange={(e) => setCallersText(e.target.value)}
            />
          </Field>
          <Field
            label="Time window"
            hint="Only release during these times, comma-separated — e.g. mon-fri 09:00-18:00. Blank = any time."
          >
            <Input
              value={windowsText}
              placeholder="blank = any time"
              onChange={(e) => setWindowsText(e.target.value)}
            />
          </Field>

          {error && <p className="text-sm text-state-deny">{error}</p>}
          <div className="flex justify-between gap-2 border-t border-border-subtle pt-4">
            <Button variant="ghost" onClick={() => setStep(0)}>
              Back
            </Button>
            <Button disabled={saveM.isPending} onClick={() => saveM.mutate()}>
              {saveM.isPending
                ? "Saving…"
                : existing
                  ? "Save changes"
                  : "Add secret"}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}
