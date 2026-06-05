import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  callerAccess,
  JudgeInfo,
  judgeList,
  judgeRemove,
  judgeSave,
  judgeSetDefault,
  judgeTest,
  judgeToggle,
  JudgeTestResult,
  keyringState,
  listVaults,
  policySurface,
  providerList,
  providerModels,
} from "../lib/api";
import { Page } from "../components/shell";
import { kindLabel, ProviderLogo } from "../components/provider-logo";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  Field,
  Input,
  Modal,
  Select,
  SubTabs,
  Textarea,
  TierBadge,
  Toggle,
} from "../components/ui";

type Tab = "judges" | "policy" | "caller";

export default function Judges() {
  const [tab, setTab] = useState<Tab>("judges");
  const qc = useQueryClient();
  const ks = useQuery({ queryKey: ["keyring-state"], queryFn: keyringState });

  const toggleM = useMutation({
    mutationFn: (v: boolean) => judgeToggle(v),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keyring-state"] }),
  });

  return (
    <Page
      title="Guardian"
      actions={
        <div className="flex items-center gap-3">
          <span className="text-sm text-content-muted">AI judge</span>
          <Toggle
            checked={ks.data?.judge_enabled ?? false}
            onChange={(v) => toggleM.mutate(v)}
          />
        </div>
      }
    >
      <SubTabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "judges", label: "Judges" },
          { value: "policy", label: "Policy surface" },
          { value: "caller", label: "Caller access" },
        ]}
      />
      {tab === "judges" && <JudgesTab />}
      {tab === "policy" && <PolicyTab />}
      {tab === "caller" && <CallerTab />}
    </Page>
  );
}

function JudgesTab() {
  const qc = useQueryClient();
  const judges = useQuery({ queryKey: ["judges"], queryFn: judgeList });
  const providers = useQuery({ queryKey: ["providers"], queryFn: providerList });
  const [wizard, setWizard] = useState<JudgeInfo | null | "new">(null);
  const [toDelete, setToDelete] = useState<JudgeInfo | null>(null);
  const [testing, setTesting] = useState<JudgeInfo | null>(null);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["judges"] });
    qc.invalidateQueries({ queryKey: ["keyring-state"] });
    qc.invalidateQueries({ queryKey: ["providers"] });
  };
  const removeM = useMutation({
    mutationFn: judgeRemove,
    onSuccess: () => {
      setToDelete(null);
      refresh();
    },
  });
  const defaultM = useMutation({ mutationFn: judgeSetDefault, onSuccess: refresh });

  const providerKindOf = (name: string | null) =>
    (providers.data ?? []).find((p) => p.name === name)?.kind;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-end">
        <Button onClick={() => setWizard("new")}>+ Add judge</Button>
      </div>

      {(judges.data ?? []).length === 0 && (
        <div className="rounded-xl border border-dashed border-border-subtle p-8 text-center text-sm text-content-muted">
          No judges yet. A judge is the AI reviewer that scores each agent
          request's reason before a medium/high secret is released.
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(judges.data ?? []).map((j) => (
          <Card key={j.name} className="flex flex-col p-4">
            <div className="flex items-center gap-2">
              {j.provider && (
                <ProviderLogo kind={providerKindOf(j.provider) ?? ""} className="size-4" />
              )}
              <span className="font-medium">{j.name}</span>
              {j.is_default && <Badge tone="judge">default</Badge>}
              {!j.has_key && <Badge tone="pending">no key</Badge>}
            </div>
            <div className="mt-1 font-mono text-xs text-content-muted">{j.model}</div>
            <div className="mt-1 text-xs text-content-muted">
              {j.provider ? `via ${j.provider}` : "own key"} · allow ≥
              {j.allow_threshold} · high ≥{j.high_threshold}
              {j.criteria && " · custom criteria"}
            </div>
            <div className="mt-3 flex items-center gap-1 border-t border-border-subtle pt-3">
              <Button
                variant="secondary"
                className="px-2 py-1 text-xs"
                onClick={() => setTesting(j)}
              >
                Test
              </Button>
              {!j.is_default && (
                <Button
                  variant="ghost"
                  className="px-2 py-1 text-xs"
                  onClick={() => defaultM.mutate(j.name)}
                >
                  Set default
                </Button>
              )}
              <Button
                variant="ghost"
                className="px-2 py-1 text-xs"
                onClick={() => setWizard(j)}
              >
                Edit
              </Button>
              <Button
                variant="ghost"
                className="ml-auto px-2 py-1 text-xs text-state-deny"
                onClick={() => setToDelete(j)}
              >
                Remove
              </Button>
            </div>
          </Card>
        ))}
      </div>

      {testing && <TestModal judge={testing} onClose={() => setTesting(null)} />}

      {wizard !== null && (
        <JudgeWizard
          existing={wizard === "new" ? null : wizard}
          onClose={() => setWizard(null)}
          onSaved={() => {
            setWizard(null);
            refresh();
          }}
        />
      )}

      {toDelete && (
        <ConfirmDialog
          title={`Remove judge "${toDelete.name}"?`}
          danger
          confirmLabel="Remove judge"
          busy={removeM.isPending}
          message={
            <>
              Vaults assigned to it fall back to the keyring's default judge;
              with no judge left, medium/high secrets become human-only.
            </>
          }
          onCancel={() => setToDelete(null)}
          onConfirm={() => removeM.mutate(toDelete.name)}
        />
      )}
    </div>
  );
}

// ── Add/edit judge wizard ────────────────────────────────────────────────────
// Three steps: provider → model (live list, with a recommendation) → tuning
// (thresholds + criteria). Without a provider there is nothing to reason with,
// so the wizard says exactly what that means instead of offering a dead end.

// Preferred judge models per provider kind, best first. The recommendation is
// the first fetched model containing one of these; otherwise the first model.
const RECOMMENDED: Record<string, string[]> = {
  openrouter: ["google/gemini-2.5-flash", "gpt-4.1-mini", "claude-haiku"],
  openai: ["gpt-4.1-mini", "gpt-4o-mini", "gpt-4.1"],
  anthropic: ["haiku", "sonnet"],
  ollama: ["llama3", "qwen", "mistral"],
  lmstudio: ["llama3", "qwen", "mistral"],
  local: ["llama3", "qwen", "mistral"],
};

function recommendModel(kind: string | undefined, models: string[]): string | null {
  if (models.length === 0) return null;
  for (const pref of RECOMMENDED[kind ?? ""] ?? []) {
    const hit = models.find((m) => m.toLowerCase().includes(pref.toLowerCase()));
    if (hit) return hit;
  }
  return models[0];
}

function JudgeWizard({
  existing,
  onClose,
  onSaved,
}: {
  existing: JudgeInfo | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const navigate = useNavigate();
  const ks = useQuery({ queryKey: ["keyring-state"], queryFn: keyringState });
  const providersQ = useQuery({ queryKey: ["providers"], queryFn: providerList });
  const providers = (providersQ.data ?? []).filter((p) => p.enabled);

  const [step, setStep] = useState(0);
  const [provider, setProvider] = useState(existing?.provider ?? "");
  const [model, setModel] = useState(existing?.model ?? "");
  const [name, setName] = useState(existing?.name ?? "");
  const [allow, setAllow] = useState(existing?.allow_threshold ?? 60);
  const [high, setHigh] = useState(existing?.high_threshold ?? 80);
  const [criteria, setCriteria] = useState(existing?.criteria ?? "");
  const [error, setError] = useState<string | null>(null);

  // Pre-select the default provider once the list arrives (new judge only).
  const effectiveProvider =
    provider ||
    (existing ? "" : (providers.find((p) => p.is_default)?.name ?? providers[0]?.name ?? ""));
  const selectedKind = providers.find((p) => p.name === effectiveProvider)?.kind;

  const models = useQuery({
    queryKey: ["provider-models", effectiveProvider],
    queryFn: () => providerModels(effectiveProvider),
    enabled: effectiveProvider !== "",
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const recommended = useMemo(
    () => recommendModel(selectedKind, models.data ?? []),
    [selectedKind, models.data],
  );
  // The dropdown's value: explicit choice, else the recommendation.
  const effectiveModel = model || recommended || "";

  const saveM = useMutation({
    mutationFn: async () => {
      await judgeSave({
        name: name.trim() || "default",
        model: effectiveModel.trim(),
        allow_threshold: allow,
        high_threshold: high,
        criteria,
        api_key: null,
        provider: effectiveProvider || null,
      });
      // Creating the first judge is the moment the gate becomes AI-aware —
      // flip the global switch on rather than leaving a silent dead toggle.
      if (!ks.data?.judge_enabled) await judgeToggle(true);
    },
    onSuccess: onSaved,
    onError: (e) => setError(String(e)),
  });

  const noProviders = providersQ.data && providers.length === 0;
  const steps = ["Provider", "Model", "Tuning"];

  return (
    <Modal
      title={existing ? `Edit judge · ${existing.name}` : "Add judge"}
      onClose={onClose}
      width="max-w-lg"
    >
      {/* Step indicator */}
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
          {noProviders ? (
            <>
              <div className="rounded-lg border border-state-pending/40 bg-state-pending/10 p-3 text-sm">
                <p className="font-medium">No AI provider available.</p>
                <p className="mt-1 text-content-muted">
                  Without a provider the judge has no model to reason with —
                  only your static policies apply, and medium/high-tier secrets
                  stay <strong>human-only</strong>. Add a provider first, then
                  come back to create a judge.
                </p>
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="ghost" onClick={onClose}>
                  Cancel
                </Button>
                <Button onClick={() => navigate("/providers")}>Add a provider</Button>
              </div>
            </>
          ) : (
            <>
              <Field
                label="Provider"
                hint="The API account this judge calls. Manage them on the AI providers screen."
              >
                <Select
                  value={effectiveProvider}
                  onChange={(e) => {
                    setProvider(e.target.value);
                    setModel("");
                  }}
                >
                  {providers.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name} ({kindLabel(p.kind)})
                    </option>
                  ))}
                </Select>
              </Field>
              <div className="flex justify-end gap-2">
                <Button variant="ghost" onClick={onClose}>
                  Cancel
                </Button>
                <Button disabled={!effectiveProvider} onClick={() => setStep(1)}>
                  Next
                </Button>
              </div>
            </>
          )}
        </div>
      )}

      {step === 1 && (
        <div className="flex flex-col gap-3">
          {models.isLoading && (
            <p className="text-sm text-content-muted">
              Loading models from {effectiveProvider}…
            </p>
          )}
          {models.data && models.data.length > 0 ? (
            <Field
              label="Model"
              hint="A cheap, fast model is ideal — the judge makes one short scoring call per request."
            >
              <Select value={effectiveModel} onChange={(e) => setModel(e.target.value)}>
                {models.data.map((m) => (
                  <option key={m} value={m}>
                    {m}
                    {m === recommended ? "  (recommended)" : ""}
                  </option>
                ))}
              </Select>
            </Field>
          ) : (
            !models.isLoading && (
              <Field
                label="Model"
                hint={
                  models.isError
                    ? `Couldn't load the model list (${String(models.error)}) — type a model id.`
                    : "Type a model id."
                }
              >
                <Input
                  value={model}
                  placeholder="e.g. google/gemini-2.5-flash"
                  onChange={(e) => setModel(e.target.value)}
                />
              </Field>
            )
          )}
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={() => setStep(0)}>
              Back
            </Button>
            <Button disabled={!effectiveModel.trim()} onClick={() => setStep(2)}>
              Next
            </Button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="flex flex-col gap-3">
          <Field label="Name" hint="How vaults refer to this judge.">
            <Input
              value={name}
              disabled={!!existing}
              placeholder="default"
              onChange={(e) => setName(e.target.value)}
            />
          </Field>

          <div className="rounded-lg border border-border-subtle bg-surface-sunken p-3 text-xs text-content-muted">
            The judge scores every request <strong>0–100</strong> on how
            plausibly the stated reason justifies access. A{" "}
            <strong>medium</strong>-tier secret is released at or above the
            Allow score; a <strong>high</strong>-tier secret needs the High
            score. Raise them for stricter gating, lower for more permissive.
          </div>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Allow score (medium)" hint="Default 60.">
              <Input
                type="number"
                min={0}
                max={100}
                value={allow}
                onChange={(e) => setAllow(Number(e.target.value))}
              />
            </Field>
            <Field label="High score (high)" hint="Default 80.">
              <Input
                type="number"
                min={0}
                max={100}
                value={high}
                onChange={(e) => setHigh(Number(e.target.value))}
              />
            </Field>
          </div>

          <Field
            label="Criteria (optional)"
            hint="Your own rules, added to the judge's prompt — e.g. 'deny anything mentioning production deploys outside business hours'."
          >
            <Textarea
              rows={3}
              value={criteria}
              onChange={(e) => setCriteria(e.target.value)}
            />
          </Field>

          {error && <p className="text-sm text-state-deny">{error}</p>}
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={() => setStep(1)}>
              Back
            </Button>
            <Button disabled={saveM.isPending} onClick={() => saveM.mutate()}>
              {saveM.isPending
                ? "Saving…"
                : existing
                  ? "Save changes"
                  : "Create judge"}
            </Button>
          </div>
        </div>
      )}
    </Modal>
  );
}

// Per-judge live test, in a modal — opened from a card's Test button rather
// than squatting on the page.
function TestModal({ judge, onClose }: { judge: JudgeInfo; onClose: () => void }) {
  const [t, setT] = useState({
    judge: judge.name,
    reason: "run the nightly database migration to apply pending changes",
    scope: "database",
    secret: "DB_PASSWORD",
    caller: "tester",
    tier: "medium",
    secret_description: "",
  });
  const [result, setResult] = useState<JudgeTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const testM = useMutation({
    mutationFn: () => judgeTest({ ...t, judge: t.judge || null }),
    onSuccess: (r) => {
      setResult(r);
      setError(null);
    },
    onError: (e) => {
      setResult(null);
      setError(String(e));
    },
  });

  return (
    <Modal title={`Live test · ${judge.name}`} onClose={onClose} width="max-w-lg">
      <p className="mb-3 text-xs text-content-muted">
        Runs the real model against a sample request — nothing is read or
        written.
      </p>
      <div className="flex flex-col gap-3">
        <Field label="Reason">
          <Textarea
            rows={2}
            value={t.reason}
            onChange={(e) => setT({ ...t, reason: e.target.value })}
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Scope">
            <Input value={t.scope} onChange={(e) => setT({ ...t, scope: e.target.value })} />
          </Field>
          <Field label="Tier">
            <Select value={t.tier} onChange={(e) => setT({ ...t, tier: e.target.value })}>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
            </Select>
          </Field>
          <Field label="Secret">
            <Input value={t.secret} onChange={(e) => setT({ ...t, secret: e.target.value })} />
          </Field>
          <Field label="Caller">
            <Input value={t.caller} onChange={(e) => setT({ ...t, caller: e.target.value })} />
          </Field>
        </div>
        <Field label="Secret description">
          <Input
            value={t.secret_description}
            onChange={(e) => setT({ ...t, secret_description: e.target.value })}
          />
        </Field>
        <Button onClick={() => testM.mutate()} disabled={testM.isPending}>
          {testM.isPending ? "Asking the model…" : "Run test"}
        </Button>
        {error && <p className="text-sm text-state-deny">{error}</p>}
        {result && (
          <div className="rounded-lg border border-border-subtle p-3 text-sm">
            <div className="mb-2 flex items-center gap-2">
              <Badge tone={result.verdict === "allow" ? "allow" : "deny"}>
                {result.verdict.toUpperCase()}
              </Badge>
              {result.score != null && <span>score {result.score}</span>}
              <span className="text-content-muted">
                (allow≥{result.allow_threshold}, high≥{result.high_threshold})
              </span>
            </div>
            <p className="text-content-muted">{result.rationale}</p>
            <p className="mt-1 text-xs text-content-muted">model: {result.model}</p>
          </div>
        )}
      </div>
    </Modal>
  );
}

function VaultPicker({
  value,
  onChange,
}: {
  value: string;
  onChange: (v: string) => void;
}) {
  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults });
  return (
    <Select className="w-64" value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">Select a vault…</option>
      {(vaults.data ?? []).map((v) => (
        <option key={v.leaf} value={v.leaf}>
          {v.name}
        </option>
      ))}
    </Select>
  );
}

function PolicyTab() {
  const [leaf, setLeaf] = useState("");
  const surface = useQuery({
    queryKey: ["policy-surface", leaf],
    queryFn: () => policySurface(leaf),
    enabled: !!leaf,
  });

  return (
    <div className="flex flex-col gap-4">
      <VaultPicker value={leaf} onChange={setLeaf} />
      {surface.data && (
        <div className="grid grid-cols-2 gap-4">
          <Card className="p-4 text-sm">
            <h3 className="mb-3 font-semibold">Access</h3>
            <Row k="Rate & burst" v={surface.data.rate_limit} />
            <Row k="Allow agent" v={surface.data.allow_agent} />
            <Row k="Default tier" v={surface.data.default_tier} />
          </Card>
          <Card className="p-4 text-sm">
            <h3 className="mb-3 font-semibold">Tiers → gate</h3>
            {surface.data.tier_gates.map((g) => (
              <Row key={g.tier} k={g.tier} v={g.gate} />
            ))}
          </Card>
          <Card className="p-4 text-sm">
            <h3 className="mb-3 font-semibold">Callers</h3>
            {surface.data.callers.length === 0 ? (
              <p className="text-content-muted">
                Fallback mode (no caller rules) — uses allow_agent / rate_limit.
              </p>
            ) : (
              surface.data.callers.map((c) => (
                <Row key={c.name} k={c.name} v={`${c.scopes.join(", ")} · ${c.rate_limit}`} />
              ))
            )}
          </Card>
          <Card className="p-4 text-sm">
            <h3 className="mb-3 font-semibold">Escalation</h3>
            <p className="text-content-muted">
              {surface.data.seal_threshold} denials within{" "}
              {surface.data.seal_window_secs}s seal the secret → human approval.
              Agents never self-clear.
            </p>
            {surface.data.conditioned.length > 0 && (
              <div className="mt-3">
                <div className="mb-1 font-medium">Conditions</div>
                {surface.data.conditioned.map((c) => (
                  <Row
                    key={c.secret}
                    k={c.secret}
                    v={[...c.windows, ...c.callers.map((x) => `caller:${x}`)].join("; ")}
                  />
                ))}
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

function CallerTab() {
  const [leaf, setLeaf] = useState("");
  const [caller, setCaller] = useState("");
  const [submitted, setSubmitted] = useState<{ leaf: string; caller: string } | null>(
    null,
  );
  const access = useQuery({
    queryKey: ["caller-access", submitted?.leaf, submitted?.caller],
    queryFn: () => callerAccess(submitted!.leaf, submitted!.caller),
    enabled: !!submitted,
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-end gap-2">
        <VaultPicker value={leaf} onChange={setLeaf} />
        <Input
          className="w-48"
          placeholder="caller name"
          value={caller}
          onChange={(e) => setCaller(e.target.value)}
        />
        <Button
          disabled={!leaf || !caller}
          onClick={() => setSubmitted({ leaf, caller })}
        >
          Check
        </Button>
      </div>
      {access.data && (
        <Card className="p-4 text-sm">
          <div className="mb-3 flex gap-6">
            <Row k="Defined" v={access.data.defined ? "yes" : "no (fallback)"} />
            <Row k="Scopes" v={access.data.scopes.join(", ") || "—"} />
            <Row k="Rate limit" v={access.data.rate_limit || "—"} />
            <Row
              k="Audit"
              v={`${access.data.audit_total} req, ${access.data.audit_denied} denied`}
            />
          </div>
          <h3 className="mb-2 font-semibold">Reachable secrets</h3>
          {access.data.accessible.length === 0 ? (
            <p className="text-content-muted">None reachable for this caller.</p>
          ) : (
            <table className="w-full">
              <tbody>
                {access.data.accessible.map((r) => (
                  <tr key={r.secret} className="border-t border-border-subtle">
                    <td className="py-1.5">{r.secret}</td>
                    <td className="py-1.5">
                      <Badge tone="neutral">{r.scope}</Badge>
                    </td>
                    <td className="py-1.5">
                      <TierBadge tier={r.tier} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {access.data.seals.length > 0 && (
            <div className="mt-4">
              <h3 className="mb-2 font-semibold text-state-pending">Active seals</h3>
              {access.data.seals.map((s) => (
                <Row key={s.secret} k={s.secret} v={`${s.trigger} (${s.last_caller})`} />
              ))}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 py-0.5">
      <span className="text-content-muted">{k}</span>
      <span className="text-right">{v}</span>
    </div>
  );
}
