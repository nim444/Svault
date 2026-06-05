import { ReactNode, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck } from "lucide-react";
import {
  judgeSave,
  judgeToggle,
  keyringState,
  listVaults,
  providerKinds,
  providerList,
  providerModels,
  providerSave,
} from "../lib/api";
import { Page } from "../components/shell";
import { Badge, Button, Card, Field, Input, Select } from "../components/ui";

// Getting-started home: the four setup steps, checked off as the store fills
// in. The index route lands here until a vault holds at least one secret.
export interface StartState {
  hasProvider: boolean;
  hasJudge: boolean;
  hasVault: boolean;
  hasSecret: boolean;
  firstVaultLeaf: string | null;
  remaining: number; // required steps left (judge is optional)
  complete: boolean;
}

export function useStartState(): StartState | null {
  const ks = useQuery({ queryKey: ["keyring-state"], queryFn: keyringState });
  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults });
  if (!ks.data || !vaults.data) return null;
  const hasProvider = ks.data.provider_count > 0;
  const hasJudge = ks.data.judge_count > 0 && ks.data.judge_enabled;
  const hasVault = vaults.data.length > 0;
  const hasSecret = vaults.data.some((v) => v.secret_count > 0);
  const remaining =
    (hasProvider ? 0 : 1) + (hasVault ? 0 : 1) + (hasSecret ? 0 : 1);
  return {
    hasProvider,
    hasJudge,
    hasVault,
    hasSecret,
    firstVaultLeaf: vaults.data[0]?.leaf ?? null,
    remaining,
    complete: remaining === 0,
  };
}

export default function Start() {
  const navigate = useNavigate();
  const state = useStartState();

  if (!state) {
    return (
      <Page title="Getting started">
        <p className="text-content-muted">Loading…</p>
      </Page>
    );
  }

  return (
    <Page
      title="Getting started"
      badge={
        state.complete ? (
          <Badge tone="allow">all set</Badge>
        ) : (
          <Badge tone="pending">{state.remaining} to go</Badge>
        )
      }
    >
      <div className="mx-auto flex max-w-2xl flex-col gap-3">
        <p className="text-sm text-content-muted">
          Set Svault up in four steps. Everything is stored encrypted under
          your master passphrase — nothing leaves this machine except judge
          calls to your AI provider.
        </p>

        <Step
          n={1}
          title="Add an AI provider"
          done={state.hasProvider}
          summary="OpenRouter, OpenAI, Anthropic, or a local endpoint (Ollama) — it powers the AI judge that reviews agent requests."
        >
          <ProviderForm />
        </Step>

        <Step
          n={2}
          title="Create a judge"
          done={state.hasJudge}
          optional
          summary="Pick a provider and a model. Without an active judge, medium/high secrets are human-only and judge options stay hidden."
          locked={!state.hasProvider}
          lockedHint="Add a provider first."
        >
          <JudgeForm />
        </Step>

        <Step
          n={3}
          title="Create a vault"
          done={state.hasVault}
          summary="A vault is an encrypted store for one project's secrets."
        >
          <Button onClick={() => navigate("/vaults/new")}>Create vault</Button>
        </Step>

        <Step
          n={4}
          title="Add a secret"
          done={state.hasSecret}
          summary="Store a secret and classify it — scope, sensitivity tier, and who may ask for it."
          locked={!state.hasVault}
          lockedHint="Create a vault first."
        >
          <Button
            onClick={() =>
              navigate(
                state.firstVaultLeaf
                  ? `/vaults/${state.firstVaultLeaf}`
                  : "/vaults",
              )
            }
          >
            Add secret
          </Button>
        </Step>

        {state.complete && (
          <div className="mt-2 flex items-center justify-between rounded-xl border border-state-allow/40 bg-state-allow/10 px-4 py-3 text-sm">
            <span>
              You're set. Wire an agent in over MCP, then watch requests land
              in the audit timeline.
            </span>
            <Button variant="secondary" onClick={() => navigate("/mcp")}>
              Open MCP
            </Button>
          </div>
        )}
      </div>
    </Page>
  );
}

function Step({
  n,
  title,
  summary,
  done,
  optional,
  locked,
  lockedHint,
  children,
}: {
  n: number;
  title: string;
  summary: string;
  done: boolean;
  optional?: boolean;
  locked?: boolean;
  lockedHint?: string;
  children: ReactNode;
}) {
  return (
    <Card className={`p-4 ${done ? "opacity-80" : ""}`}>
      <div className="flex items-start gap-3">
        {done ? (
          <CircleCheck
            className="mt-0.5 size-5 shrink-0"
            style={{ color: "var(--state-allow)" }}
          />
        ) : (
          <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-border-subtle text-xs text-content-muted">
            {n}
          </span>
        )}
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold">{title}</h2>
            {optional && <Badge tone="neutral">optional</Badge>}
            {done && <Badge tone="allow">done</Badge>}
          </div>
          <p className="mt-1 text-sm text-content-muted">{summary}</p>
          {!done &&
            (locked ? (
              <p className="mt-3 text-xs text-content-muted">{lockedHint}</p>
            ) : (
              <div className="mt-3">{children}</div>
            ))}
        </div>
      </div>
    </Card>
  );
}

// Step 1 — inline provider form: pick a kind, paste a key (local endpoints
// need none). The provider is named after its kind; fine-tuning (base URL,
// more providers) lives on the AI providers screen.
function ProviderForm() {
  const qc = useQueryClient();
  const kinds = useQuery({ queryKey: ["provider-kinds"], queryFn: providerKinds });
  const [kind, setKind] = useState("openrouter");
  const [key, setKey] = useState("");
  const kindInfo = (kinds.data ?? []).find((k) => k.kind === kind);
  const save = useMutation({
    mutationFn: () =>
      providerSave({ name: kind, kind, base_url: "", api_key: key }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["keyring-state"] });
      qc.invalidateQueries({ queryKey: ["providers"] });
    },
  });
  const canSave = kindInfo?.key_optional ? true : key.trim() !== "";
  return (
    <div className="flex max-w-md flex-col gap-2">
      <Field label="Provider" hint="More kinds and options on the AI providers screen.">
        <Select value={kind} onChange={(e) => setKind(e.target.value)}>
          {(kinds.data ?? []).map((k) => (
            <option key={k.kind} value={k.kind}>
              {k.kind}
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label={kindInfo?.key_optional ? "API key (optional)" : "API key"}
        hint="Stored encrypted in the keyring; only ever sent to this provider."
      >
        <Input
          type="password"
          placeholder={kindInfo?.key_optional ? "none needed for local endpoints" : "sk-…"}
          value={key}
          onChange={(e) => setKey(e.target.value)}
        />
      </Field>
      {save.error && (
        <p className="text-xs text-state-deny">{String(save.error)}</p>
      )}
      <div>
        <Button disabled={!canSave || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? "Saving…" : "Save provider"}
        </Button>
      </div>
    </div>
  );
}

// Step 2 — minimal judge creation: provider + model, sane defaults for the
// rest (thresholds/criteria are tunable later on the Judges screen). Creating
// it also flips the global judge switch on.
function JudgeForm() {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: providerList });
  const enabled = (providers.data ?? []).filter((p) => p.enabled);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("google/gemini-2.5-flash");
  const effective = provider || enabled.find((p) => p.is_default)?.name || enabled[0]?.name || "";
  const models = useQuery({
    queryKey: ["provider-models", effective],
    queryFn: () => providerModels(effective),
    enabled: effective !== "",
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
  const save = useMutation({
    mutationFn: async () => {
      await judgeSave({
        name: "default",
        model: model.trim(),
        allow_threshold: 60,
        high_threshold: 80,
        criteria: "",
        api_key: null,
        provider: effective || null,
      });
      await judgeToggle(true);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keyring-state"] }),
  });
  return (
    <div className="flex max-w-md flex-col gap-2">
      <Field label="Provider">
        <Select value={effective} onChange={(e) => setProvider(e.target.value)}>
          {enabled.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name} ({p.kind})
            </option>
          ))}
        </Select>
      </Field>
      <Field
        label="Model"
        hint="A cheap, fast model works well as a judge. The list is live from the provider; free text works too."
      >
        <Input
          list="start-judge-models"
          value={model}
          onChange={(e) => setModel(e.target.value)}
        />
        <datalist id="start-judge-models">
          {(models.data ?? []).map((m) => (
            <option key={m} value={m} />
          ))}
        </datalist>
      </Field>
      {save.error && (
        <p className="text-xs text-state-deny">{String(save.error)}</p>
      )}
      <div>
        <Button disabled={!model.trim() || save.isPending} onClick={() => save.mutate()}>
          {save.isPending ? "Creating…" : "Create judge"}
        </Button>
      </div>
    </div>
  );
}
