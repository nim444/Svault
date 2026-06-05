import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  callerAccess,
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
import {
  Badge,
  Button,
  Card,
  Field,
  Input,
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
      title="Judges & Policy"
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
          { value: "judges", label: "Judges & test" },
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

const blankJudge = {
  name: "",
  model: "google/gemini-2.5-flash",
  allow_threshold: 60,
  high_threshold: 80,
  criteria: "",
  api_key: "",
  provider: "",
};

function JudgesTab() {
  const qc = useQueryClient();
  const judges = useQuery({ queryKey: ["judges"], queryFn: judgeList });
  const providers = useQuery({ queryKey: ["providers"], queryFn: providerList });
  const [editor, setEditor] = useState({ ...blankJudge });
  const [error, setError] = useState<string | null>(null);

  // Only enabled providers are selectable; pre-select the default one on a
  // fresh form so the common path is pick-a-model-and-save.
  const enabledProviders = (providers.data ?? []).filter((p) => p.enabled);
  useEffect(() => {
    if (editor.name === "" && editor.provider === "") {
      const def = enabledProviders.find((p) => p.is_default);
      if (def) setEditor((e) => ({ ...e, provider: def.name }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [providers.data]);

  // Live model list for the selected provider — datalist suggestions with
  // free-text fallback if the fetch fails.
  const models = useQuery({
    queryKey: ["provider-models", editor.provider],
    queryFn: () => providerModels(editor.provider),
    enabled: editor.provider !== "",
    staleTime: 5 * 60 * 1000,
    retry: false,
  });

  const saveM = useMutation({
    mutationFn: () =>
      judgeSave({
        ...editor,
        api_key: editor.api_key || null,
        provider: editor.provider || null,
      }),
    onSuccess: () => {
      setEditor({ ...blankJudge });
      setError(null);
      qc.invalidateQueries({ queryKey: ["judges"] });
      qc.invalidateQueries({ queryKey: ["keyring-state"] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
    onError: (e) => setError(String(e)),
  });
  const removeM = useMutation({
    mutationFn: judgeRemove,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["judges"] }),
  });
  const defaultM = useMutation({
    mutationFn: judgeSetDefault,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["judges"] }),
  });

  return (
    <div className="grid grid-cols-2 gap-6">
      <div className="flex flex-col gap-4">
        <Card className="p-4">
          <h3 className="mb-3 text-sm font-semibold">Registry</h3>
          {(judges.data ?? []).length === 0 && (
            <p className="text-sm text-content-muted">No judges yet. Add one →</p>
          )}
          <div className="flex flex-col gap-2">
            {(judges.data ?? []).map((j) => (
              <div
                key={j.name}
                className="flex items-center justify-between rounded-lg border border-border-subtle p-2.5 text-sm"
              >
                <div>
                  <div className="flex items-center gap-2 font-medium">
                    {j.is_default && <span title="Default">★</span>}
                    {j.name}
                    {!j.has_key && <Badge tone="pending">no key</Badge>}
                  </div>
                  <div className="text-xs text-content-muted">
                    {j.model}
                    {j.provider && <> · via {j.provider}</>}
                  </div>
                </div>
                <div className="flex gap-1">
                  <Button
                    variant="ghost"
                    className="px-2 py-1 text-xs"
                    onClick={() =>
                      setEditor({
                        name: j.name,
                        model: j.model,
                        allow_threshold: j.allow_threshold,
                        high_threshold: j.high_threshold,
                        criteria: j.criteria,
                        api_key: "",
                        provider: j.provider ?? "",
                      })
                    }
                  >
                    Edit
                  </Button>
                  {!j.is_default && (
                    <Button
                      variant="ghost"
                      className="px-2 py-1 text-xs"
                      onClick={() => defaultM.mutate(j.name)}
                    >
                      Set ★
                    </Button>
                  )}
                  <Button
                    variant="ghost"
                    className="px-2 py-1 text-xs text-state-deny"
                    onClick={() => removeM.mutate(j.name)}
                  >
                    ✕
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h3 className="mb-3 text-sm font-semibold">
            {editor.name ? `Editor · ${editor.name}` : "New judge"}
          </h3>
          <div className="flex flex-col gap-3">
            <Field label="Name">
              <Input
                value={editor.name}
                onChange={(e) => setEditor({ ...editor, name: e.target.value })}
              />
            </Field>
            <Field
              label="Model"
              hint={
                models.data
                  ? "Live list from the provider; free text works too."
                  : "Type a model id; the list loads when a provider is selected."
              }
            >
              <Input
                list="judge-model-options"
                value={editor.model}
                onChange={(e) => setEditor({ ...editor, model: e.target.value })}
              />
              <datalist id="judge-model-options">
                {(models.data ?? []).map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Allow ≥">
                <Input
                  type="number"
                  value={editor.allow_threshold}
                  onChange={(e) =>
                    setEditor({ ...editor, allow_threshold: Number(e.target.value) })
                  }
                />
              </Field>
              <Field label="High ≥">
                <Input
                  type="number"
                  value={editor.high_threshold}
                  onChange={(e) =>
                    setEditor({ ...editor, high_threshold: Number(e.target.value) })
                  }
                />
              </Field>
            </div>
            <Field label="Criteria" hint="Injected into the judge's prompt.">
              <Textarea
                rows={3}
                value={editor.criteria}
                onChange={(e) => setEditor({ ...editor, criteria: e.target.value })}
              />
            </Field>
            <Field
              label="Provider"
              hint="The judge draws its API key from this provider. 'Own key' keeps a key on the judge itself."
            >
              <Select
                value={editor.provider}
                onChange={(e) => setEditor({ ...editor, provider: e.target.value })}
              >
                <option value="">own key</option>
                {enabledProviders.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name} ({p.kind})
                  </option>
                ))}
              </Select>
            </Field>
            {!editor.provider && (
              <Field label="API key" hint="Stored encrypted. Blank = keep / use $SVAULT_OPENROUTER_KEY.">
                <Input
                  type="password"
                  placeholder={editor.name ? "unchanged" : ""}
                  value={editor.api_key}
                  onChange={(e) => setEditor({ ...editor, api_key: e.target.value })}
                />
              </Field>
            )}
            {error && <p className="text-sm text-state-deny">{error}</p>}
            <div className="flex gap-2">
              {editor.name && (
                <Button variant="ghost" onClick={() => setEditor({ ...blankJudge })}>
                  Clear
                </Button>
              )}
              <Button
                disabled={saveM.isPending || !editor.name.trim()}
                onClick={() => saveM.mutate()}
              >
                Save judge
              </Button>
            </div>
          </div>
        </Card>
      </div>

      <TestBench />
    </div>
  );
}

function TestBench() {
  const [t, setT] = useState({
    judge: "",
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
    <Card className="h-fit p-4">
      <h3 className="mb-3 text-sm font-semibold">Live test</h3>
      <p className="mb-3 text-xs text-content-muted">
        Runs the real model against a sample request.
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
    </Card>
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
