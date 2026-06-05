import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  auditCallers,
  auditEvents,
  AuditEvent,
  exportLog,
  listVaults,
} from "../lib/api";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import { Badge, Button, Card, Select } from "../components/ui";

// Screen 08 — activity timeline. Polls so it streams while the daemon/MCP are
// active; Pause stops the refresh. Shows the real peer UID + real denial reason.
export default function Audit() {
  const [result, setResult] = useState("all");
  const [vault, setVault] = useState("");
  const [caller, setCaller] = useState("");
  const [paused, setPaused] = useState(false);

  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults });
  const callers = useQuery({ queryKey: ["audit-callers"], queryFn: auditCallers });

  const events = useQuery({
    queryKey: ["audit", result, vault, caller],
    queryFn: () => auditEvents({ result, vault, caller, limit: 500 }),
    refetchInterval: paused ? false : 1500,
  });

  async function onExport() {
    if (!vault) return;
    const path = await saveDialog({
      defaultPath: `${vault}-audit.json`,
      title: "Export audit log",
    });
    if (typeof path === "string") await exportLog(vault, path);
  }

  return (
    <Page
      title="Audit"
      actions={
        <>
          <Button variant="secondary" onClick={() => setPaused((p) => !p)}>
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="secondary" disabled={!vault} onClick={onExport}>
            Export log
          </Button>
        </>
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Select className="w-36" value={result} onChange={(e) => setResult(e.target.value)}>
          <option value="all">All</option>
          <option value="allowed">Allowed</option>
          <option value="denied">Denied</option>
          <option value="judge">Judge</option>
        </Select>
        <Select className="w-44" value={vault} onChange={(e) => setVault(e.target.value)}>
          <option value="">All vaults</option>
          {(vaults.data ?? []).map((v) => (
            <option key={v.leaf} value={v.leaf}>
              {v.name}
            </option>
          ))}
        </Select>
        <Select className="w-44" value={caller} onChange={(e) => setCaller(e.target.value)}>
          <option value="">All callers</option>
          {(callers.data ?? []).map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </Select>
      </div>

      {(events.data ?? []).length === 0 ? (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          No matching activity.
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {events.data!.map((e, i) => (
            <EventRow key={`${e.vault_leaf}-${e.ts}-${i}`} e={e} />
          ))}
        </div>
      )}
    </Page>
  );
}

export function decisionTone(decision: string): "allow" | "deny" | "pending" {
  if (decision === "allow") return "allow";
  if (decision === "deny") return "deny";
  return "pending";
}

export function EventRow({ e }: { e: AuditEvent }) {
  return (
    <Card className="p-3 text-sm">
      <div className="flex items-center gap-2">
        <Badge tone={decisionTone(e.decision)}>{e.decision.toUpperCase()}</Badge>
        <span className="font-medium">{e.secret || "—"}</span>
        {e.scope && <Badge tone="neutral">{e.scope}</Badge>}
        {e.tier && <Badge tone="neutral">{e.tier}</Badge>}
        <span className="ml-auto text-xs text-content-muted">
          {e.source} · {shortTime(e.unix)}
        </span>
      </div>
      <div className="mt-1 text-xs text-content-muted">
        caller <strong>{e.caller || "—"}</strong>
        {e.peer_uid != null && <> · uid {e.peer_uid}</>}
        {e.reason && <> · reason: {e.reason}</>}
        {e.rule && <> · {e.rule}</>}
      </div>
    </Card>
  );
}
