import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  exportVault,
  importVault,
  listVaults,
  recoveryStatus,
  rotateCode,
} from "../lib/api";
import { Page } from "../components/shell";
import {
  Badge,
  Button,
  Card,
  Field,
  Input,
  Modal,
  Select,
  SubTabs,
} from "../components/ui";

type Tab = "io" | "recovery";

export default function Backup() {
  const [tab, setTab] = useState<Tab>("io");
  return (
    <Page title="Backup & recovery">
      <SubTabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "io", label: "Export & import" },
          { value: "recovery", label: "Recovery code" },
        ]}
      />
      {tab === "io" && <IoTab />}
      {tab === "recovery" && <RecoveryTab />}
    </Page>
  );
}

function IoTab() {
  const qc = useQueryClient();
  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults });
  const [exportLeaf, setExportLeaf] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  const [importPath, setImportPath] = useState("");
  const [importName, setImportName] = useState("");
  const [importCode, setImportCode] = useState("");

  const exportM = useMutation({
    mutationFn: async () => {
      const v = (vaults.data ?? []).find((x) => x.leaf === exportLeaf);
      const path = await saveDialog({
        defaultPath: `${v?.name ?? exportLeaf}.svault-export.json`,
        title: "Export vault",
      });
      if (typeof path !== "string") return null;
      await exportVault(exportLeaf, path);
      return path;
    },
    onSuccess: (p) => p && setStatus(`Exported to ${p}`),
    onError: (e) => setStatus(String(e)),
  });

  const importM = useMutation({
    mutationFn: () =>
      importVault(importPath, importName.trim() || null, importCode),
    onSuccess: (name) => {
      setStatus(`Imported as ${name}`);
      setImportPath("");
      setImportCode("");
      setImportName("");
      qc.invalidateQueries({ queryKey: ["vaults"] });
    },
    onError: (e) => setStatus(String(e)),
  });

  async function pickBundle() {
    const f = await openDialog({
      title: "Select a .svault-export.json bundle",
      filters: [{ name: "Svault export", extensions: ["json"] }],
    });
    if (typeof f === "string") setImportPath(f);
  }

  return (
    <div className="grid max-w-3xl grid-cols-2 gap-4">
      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Export</h3>
        <p className="mb-3 text-xs text-content-muted">
          Encrypted, checksummed, no machine-specific state — safe to move.
        </p>
        <Field label="Vault">
          <Select value={exportLeaf} onChange={(e) => setExportLeaf(e.target.value)}>
            <option value="">Select…</option>
            {(vaults.data ?? []).map((v) => (
              <option key={v.leaf} value={v.leaf}>
                {v.name}
              </option>
            ))}
          </Select>
        </Field>
        <Button
          className="mt-3"
          disabled={!exportLeaf || exportM.isPending}
          onClick={() => exportM.mutate()}
        >
          Export
        </Button>
      </Card>

      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Import</h3>
        <div className="flex flex-col gap-3">
          <Field label="Bundle">
            <div className="flex gap-2">
              <Input readOnly value={importPath} placeholder="no file selected" />
              <Button variant="secondary" onClick={pickBundle}>
                Browse
              </Button>
            </div>
          </Field>
          <Field label="Import as" hint="Blank = bundle's own name (auto-suffixed on collision).">
            <Input value={importName} onChange={(e) => setImportName(e.target.value)} />
          </Field>
          <Field label="Recovery code" hint="Attaches the vault to this machine's master.">
            <Input value={importCode} onChange={(e) => setImportCode(e.target.value)} />
          </Field>
          <Button
            disabled={!importPath || !importCode || importM.isPending}
            onClick={() => importM.mutate()}
          >
            Import &amp; attach
          </Button>
        </div>
      </Card>

      {status && <p className="col-span-2 text-sm text-content-muted">{status}</p>}
    </div>
  );
}

function RecoveryTab() {
  const statusQ = useQuery({ queryKey: ["recovery-status"], queryFn: recoveryStatus });
  const [newCode, setNewCode] = useState<string | null>(null);
  const rotateM = useMutation({
    mutationFn: rotateCode,
    onSuccess: (code) => setNewCode(code),
  });

  return (
    <div className="max-w-2xl">
      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Recovery code status</h3>
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase text-content-muted">
            <tr>
              <th className="py-1">Vault</th>
              <th className="py-1">Code</th>
              <th className="py-1"></th>
            </tr>
          </thead>
          <tbody>
            {(statusQ.data ?? []).map((r) => (
              <tr key={r.vault_leaf} className="border-t border-border-subtle">
                <td className="py-2">{r.vault_name}</td>
                <td className="py-2">
                  {r.has_code ? (
                    <Badge tone="allow">set</Badge>
                  ) : (
                    <Badge tone="pending">none</Badge>
                  )}
                </td>
                <td className="py-2 text-right">
                  <Button
                    variant="secondary"
                    className="px-2 py-1 text-xs"
                    onClick={() => rotateM.mutate(r.vault_leaf)}
                  >
                    Rotate
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-content-muted">
          Codes are shown once and never stored in plaintext. Rotating invalidates
          the old code.
        </p>
      </Card>

      {newCode && (
        <Modal title="New recovery code" onClose={() => setNewCode(null)}>
          <p className="text-sm text-content-muted">
            Save this now — it replaces the previous code, which no longer works.
          </p>
          <div className="my-4 rounded-lg border border-state-pending/30 bg-state-pending/10 p-3 text-center font-mono text-sm">
            {newCode}
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => writeText(newCode)}>
              Copy
            </Button>
            <Button onClick={() => setNewCode(null)}>Done</Button>
          </div>
        </Modal>
      )}
    </div>
  );
}
