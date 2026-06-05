import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ProviderInfo,
  providerKinds,
  providerList,
  providerModels,
  providerRemove,
  providerSave,
  providerSetDefault,
  providerToggle,
} from "../lib/api";
import { Page } from "../components/shell";
import {
  Badge,
  Button,
  Card,
  ConfirmDialog,
  Field,
  Input,
  Modal,
  Select,
  Toast,
  Toggle,
} from "../components/ui";

// AI providers — the API accounts judges draw their credentials from.
// OpenRouter / OpenAI / Anthropic / local (Ollama, LM Studio); each kind only
// changes the default base URL and auth, the judge transport is shared.
export default function Providers() {
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: providerList });
  const kinds = useQuery({ queryKey: ["provider-kinds"], queryFn: providerKinds });
  const [editor, setEditor] = useState<ProviderEditor | null>(null);
  const [toDelete, setToDelete] = useState<ProviderInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{
    name: string;
    ok: boolean;
    msg: string;
  } | null>(null);

  const refresh = () => {
    setError(null);
    qc.invalidateQueries({ queryKey: ["providers"] });
    qc.invalidateQueries({ queryKey: ["keyring-state"] });
    qc.invalidateQueries({ queryKey: ["judges"] });
  };
  const toggleM = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      providerToggle(name, enabled),
    onSuccess: refresh,
    onError: (e) => setError(String(e)),
  });
  const defaultM = useMutation({
    mutationFn: providerSetDefault,
    onSuccess: refresh,
    onError: (e) => setError(String(e)),
  });
  const removeM = useMutation({
    mutationFn: providerRemove,
    onSuccess: () => {
      setToDelete(null);
      refresh();
    },
    onError: (e) => {
      setToDelete(null);
      setError(String(e));
    },
  });
  // "Test" = live-fetch the provider's /models. A reply proves the base URL
  // and key actually work; the error is shown verbatim otherwise.
  const testM = useMutation({
    mutationFn: (name: string) => providerModels(name),
    onSuccess: (models, name) =>
      setTestResult({
        name,
        ok: true,
        msg: `valid — ${models.length} models available`,
      }),
    onError: (e, name) => setTestResult({ name, ok: false, msg: String(e) }),
  });

  const list = providers.data ?? [];

  return (
    <Page
      title="AI providers"
      badge={<Badge tone="neutral">judges draw keys from these</Badge>}
      actions={
        <Button onClick={() => setEditor(blankEditor(kinds.data?.[0]?.kind))}>
          + Add provider
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        {error && <p className="text-sm text-state-deny">{error}</p>}

        {providers.data && list.length === 0 && (
          <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
            No providers yet. Add your OpenRouter, OpenAI, Anthropic, or local
            (Ollama) account — judges then pick a provider instead of carrying
            their own key.
          </div>
        )}

        {/* Responsive tile grid: 1-up narrow, growing right and down on wide windows. */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((p) => (
            <Card
              key={p.name}
              className={`flex flex-col p-4 ${p.enabled ? "" : "opacity-60"}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{p.name}</span>
                  <Badge tone="neutral">{p.kind}</Badge>
                  {p.is_default && <Badge tone="judge">default</Badge>}
                  {!p.has_key && p.kind !== "local" && (
                    <Badge tone="pending">no key</Badge>
                  )}
                  {!p.enabled && <Badge tone="deny">disabled</Badge>}
                </div>
                <Toggle
                  checked={p.enabled}
                  onChange={(v) => toggleM.mutate({ name: p.name, enabled: v })}
                />
              </div>

              <div className="mt-2 truncate font-mono text-xs text-content-muted">
                {p.base_url}
              </div>
              <div className="mt-1 text-xs text-content-muted">
                {p.used_by.length > 0
                  ? `used by ${p.used_by.join(", ")}`
                  : "not used by any judge yet"}
              </div>
              <div className="mt-3 flex items-center gap-1 border-t border-border-subtle pt-3">
                <Button
                  variant="secondary"
                  className="px-2 py-1 text-xs"
                  disabled={testM.isPending}
                  onClick={() => {
                    setTestResult(null);
                    testM.mutate(p.name);
                  }}
                >
                  {testM.isPending && testM.variables === p.name
                    ? "Testing…"
                    : "Test"}
                </Button>
                {!p.is_default && (
                  <Button
                    variant="ghost"
                    className="px-2 py-1 text-xs"
                    onClick={() => defaultM.mutate(p.name)}
                  >
                    Set default
                  </Button>
                )}
                <Button
                  variant="ghost"
                  className="px-2 py-1 text-xs"
                  onClick={() =>
                    setEditor({
                      name: p.name,
                      kind: p.kind,
                      base_url: p.base_url,
                      api_key: "",
                      editing: true,
                    })
                  }
                >
                  Edit
                </Button>
                <Button
                  variant="ghost"
                  className="ml-auto px-2 py-1 text-xs text-state-deny"
                  onClick={() => setToDelete(p)}
                >
                  Remove
                </Button>
              </div>
            </Card>
          ))}
        </div>

        <p className="text-xs text-content-muted">
          Disabling a provider lends no credentials: its judges go keyless and
          medium/high secrets fall back to human-only — nothing is deleted.
          Removing a provider is refused while a judge still references it.
        </p>
      </div>

      {testResult && (
        <Toast
          tone={testResult.ok ? "allow" : "deny"}
          onDone={() => setTestResult(null)}
          duration={testResult.ok ? 2000 : 5000}
        >
          <span className="font-medium">{testResult.name}:</span> {testResult.msg}
        </Toast>
      )}

      {editor && (
        <EditorModal
          editor={editor}
          setEditor={setEditor}
          onSaved={refresh}
          kinds={kinds.data ?? []}
        />
      )}

      {toDelete && (
        <ConfirmDialog
          title={`Remove provider "${toDelete.name}"?`}
          danger
          confirmLabel="Remove provider"
          busy={removeM.isPending}
          message={
            toDelete.used_by.length > 0 ? (
              <>
                This provider is used by <strong>{toDelete.used_by.join(", ")}</strong>{" "}
                — removal will be refused. Reassign or remove those judges first.
              </>
            ) : (
              <>Its stored API key is deleted from the keyring. This cannot be undone.</>
            )
          }
          onCancel={() => setToDelete(null)}
          onConfirm={() => removeM.mutate(toDelete.name)}
        />
      )}
    </Page>
  );
}

interface ProviderEditor {
  name: string;
  kind: string;
  base_url: string;
  api_key: string;
  editing: boolean;
}

function blankEditor(kind = "openrouter"): ProviderEditor {
  return { name: "", kind, base_url: "", api_key: "", editing: false };
}

function EditorModal({
  editor,
  setEditor,
  onSaved,
  kinds,
}: {
  editor: ProviderEditor;
  setEditor: (e: ProviderEditor | null) => void;
  onSaved: () => void;
  kinds: { kind: string; base_url: string; key_optional: boolean }[];
}) {
  const [error, setError] = useState<string | null>(null);
  const kindInfo = kinds.find((k) => k.kind === editor.kind);
  const saveM = useMutation({
    mutationFn: () =>
      providerSave({
        name: editor.name,
        kind: editor.kind,
        base_url: editor.base_url,
        api_key: editor.api_key,
      }),
    onSuccess: () => {
      setEditor(null);
      onSaved();
    },
    onError: (e) => setError(String(e)),
  });

  const keyNeeded = !kindInfo?.key_optional;
  const canSave =
    editor.name.trim() !== "" &&
    (editor.editing || !keyNeeded || editor.api_key.trim() !== "");

  return (
    <Modal
      title={editor.editing ? `Edit · ${editor.name}` : "New provider"}
      onClose={() => setEditor(null)}
    >
      <div className="flex flex-col gap-3">
        <Field label="Kind" hint="Decides the default endpoint and auth. All kinds use the same judge transport.">
          <Select
            value={editor.kind}
            disabled={editor.editing}
            onChange={(e) => {
              const kind = e.target.value;
              const info = kinds.find((k) => k.kind === kind);
              setEditor({
                ...editor,
                kind,
                base_url: info?.base_url ?? "",
                name: editor.editing || editor.name.trim() !== "" ? editor.name : kind,
              });
            }}
          >
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.kind}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Name">
          <Input
            value={editor.name}
            disabled={editor.editing}
            placeholder={editor.kind}
            onChange={(e) => setEditor({ ...editor, name: e.target.value })}
          />
        </Field>
        <Field label="Base URL" hint="Blank = the kind's default.">
          <Input
            className="font-mono"
            value={editor.base_url}
            placeholder={kindInfo?.base_url}
            onChange={(e) => setEditor({ ...editor, base_url: e.target.value })}
          />
        </Field>
        <Field
          label={kindInfo?.key_optional ? "API key (optional)" : "API key"}
          hint="Stored encrypted in the keyring; only ever sent to this provider."
        >
          <Input
            type="password"
            placeholder={
              editor.editing
                ? "unchanged"
                : kindInfo?.key_optional
                  ? "none needed for local endpoints"
                  : ""
            }
            value={editor.api_key}
            onChange={(e) => setEditor({ ...editor, api_key: e.target.value })}
          />
        </Field>
        {error && <p className="text-sm text-state-deny">{error}</p>}
        <div className="mt-1 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setEditor(null)}>
            Cancel
          </Button>
          <Button disabled={!canSave || saveM.isPending} onClick={() => saveM.mutate()}>
            {saveM.isPending ? "Saving…" : editor.editing ? "Save changes" : "Add provider"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
