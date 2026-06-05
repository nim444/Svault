import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import {
  auditEvents,
  connectedAgents,
  keyringState,
  mcpConfigSnippet,
  mcpToggle,
  storePath,
  writeMcpConfig,
} from "../lib/api";
import { shortTime } from "../lib/time";
import { Page } from "../components/shell";
import { Button, Card, Field, Input, Segmented, Select, SubTabs, Toggle } from "../components/ui";
import { EventRow } from "./Audit";

type Tab = "connection" | "wiring" | "log";

export default function Mcp() {
  const [tab, setTab] = useState<Tab>("connection");
  const qc = useQueryClient();
  const ks = useQuery({ queryKey: ["keyring-state"], queryFn: keyringState });
  const toggleM = useMutation({
    mutationFn: mcpToggle,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["keyring-state"] }),
  });

  return (
    <Page
      title="MCP"
      actions={
        <div className="flex items-center gap-3">
          <span className="text-sm text-content-muted">Server</span>
          <Toggle
            checked={ks.data?.mcp_enabled ?? true}
            onChange={(v) => toggleM.mutate(v)}
          />
        </div>
      }
    >
      <SubTabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "connection", label: "Connection & tools" },
          { value: "wiring", label: "Wiring" },
          { value: "log", label: "Live log" },
        ]}
      />
      {tab === "connection" && <ConnectionTab />}
      {tab === "wiring" && <WiringTab />}
      {tab === "log" && <LogTab />}
    </Page>
  );
}

function ConnectionTab() {
  const agents = useQuery({ queryKey: ["agents"], queryFn: connectedAgents });
  return (
    <div className="flex flex-col gap-5">
      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Connected agents</h3>
        {(agents.data ?? []).length === 0 ? (
          <p className="text-sm text-content-muted">No agents have called through the door yet.</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase text-content-muted">
              <tr>
                <th className="py-1">Caller</th>
                <th className="py-1">Peer UID</th>
                <th className="py-1">Last call</th>
                <th className="py-1">Calls today</th>
              </tr>
            </thead>
            <tbody>
              {agents.data!.map((a) => (
                <tr key={a.caller} className="border-t border-border-subtle">
                  <td className="py-1.5 font-medium">{a.caller}</td>
                  <td className="py-1.5 text-content-muted">{a.peer_uid ?? "—"}</td>
                  <td className="py-1.5 text-content-muted">{shortTime(a.last_call)}</td>
                  <td className="py-1.5">{a.calls_today}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <div className="grid grid-cols-2 gap-4">
        <ToolCard
          name="svault_get_secret"
          desc="The gated agent path."
          req="name, scope, reason (≥10 chars)"
          opt="vault, caller"
        />
        <ToolCard
          name="svault_list_vaults"
          desc="Names + lock state. Safe — no args."
          req="—"
          opt="—"
        />
      </div>
      <p className="text-xs text-content-muted">
        The capability descriptor advertises the request <em>interface</em>, never
        the decision criteria.
      </p>
    </div>
  );
}

function ToolCard({
  name,
  desc,
  req,
  opt,
}: {
  name: string;
  desc: string;
  req: string;
  opt: string;
}) {
  return (
    <Card className="p-4 text-sm">
      <div className="font-mono font-medium">{name}</div>
      <p className="mb-2 text-content-muted">{desc}</p>
      <div className="text-xs">
        <span className="text-content-muted">required:</span> {req}
      </div>
      <div className="text-xs">
        <span className="text-content-muted">optional:</span> {opt}
      </div>
    </Card>
  );
}

function WiringTab() {
  const [client, setClient] = useState<"claude" | "cursor" | "vscode">("claude");
  const [bin, setBin] = useState("svault");
  const [caller, setCaller] = useState("my-agent");
  const store = useQuery({ queryKey: ["store-path"], queryFn: storePath });
  const snippet = useQuery({
    queryKey: ["mcp-snippet", bin, caller],
    queryFn: () => mcpConfigSnippet(bin, caller),
  });
  const [status, setStatus] = useState<string | null>(null);

  async function writeConfig() {
    const dir = await openDialog({ directory: true, title: "Pick the project folder" });
    if (typeof dir !== "string") return;
    try {
      await writeMcpConfig(`${dir}/.mcp.json`, bin, caller);
      setStatus(`Wrote ${dir}/.mcp.json`);
    } catch (e) {
      setStatus(String(e));
    }
  }

  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <Segmented
        value={client}
        onChange={setClient}
        options={[
          { value: "claude", label: "Claude Code" },
          { value: "cursor", label: "Cursor" },
          { value: "vscode", label: "VS Code" },
        ]}
      />
      <div className="grid grid-cols-2 gap-3">
        <Field label="Binary path" hint="The bundled sidecar, or 'svault' on PATH.">
          <Input value={bin} onChange={(e) => setBin(e.target.value)} />
        </Field>
        <Field label="SVAULT_CALLER">
          <Input value={caller} onChange={(e) => setCaller(e.target.value)} />
        </Field>
      </div>
      <Card className="p-0">
        <pre className="overflow-auto rounded-xl bg-surface-sunken p-4 text-xs">
          {snippet.data ?? ""}
        </pre>
      </Card>
      <div className="flex gap-2">
        <Button variant="secondary" onClick={() => writeText(snippet.data ?? "")}>
          Copy
        </Button>
        <Button onClick={writeConfig}>Write to ./.mcp.json</Button>
      </div>
      {status && <p className="text-sm text-content-muted">{status}</p>}
      <Card className="p-4 text-sm">
        <Row k="Store path" v={store.data ?? "…"} />
        <Row k="Transport" v="stdio JSON-RPC 2.0" />
      </Card>
      <p className="text-xs text-content-muted">
        How the door behaves: no passphrase reaches the server; a locked vault tells
        the agent to ask a human; denials are generic; sealed stays sealed.
      </p>
    </div>
  );
}

function LogTab() {
  const [result, setResult] = useState("all");
  const [paused, setPaused] = useState(false);
  const events = useQuery({
    queryKey: ["mcp-log", result],
    queryFn: () => auditEvents({ source: "mcp", result, limit: 300 }),
    refetchInterval: paused ? false : 1500,
  });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Select className="w-36" value={result} onChange={(e) => setResult(e.target.value)}>
          <option value="all">All</option>
          <option value="allowed">Allow</option>
          <option value="denied">Deny</option>
        </Select>
        <Button variant="secondary" onClick={() => setPaused((p) => !p)}>
          {paused ? "Resume" : "Pause"}
        </Button>
      </div>
      {(events.data ?? []).length === 0 ? (
        <div className="rounded-xl border border-dashed border-border-subtle p-10 text-center text-content-muted">
          No MCP activity yet. Tool calls appear here (metadata + verdict only —
          values are never logged).
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {events.data!.map((e, i) => (
            <EventRow key={`${e.ts}-${i}`} e={e} />
          ))}
        </div>
      )}
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 py-0.5">
      <span className="text-content-muted">{k}</span>
      <span className="truncate text-right font-mono text-xs">{v}</span>
    </div>
  );
}
