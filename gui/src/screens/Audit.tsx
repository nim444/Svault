import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ColumnDef } from "@tanstack/react-table";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";
import {
  activityEvents,
  ActivityEvent,
  auditCallers,
  auditEvents,
  AuditEvent,
  exportLog,
  listVaults,
} from "../lib/api";
import { fullTime, sourceLabel } from "../lib/time";
import { Page } from "../components/shell";
import { DataTable } from "../components/data-table";
import { Badge, Button, Card, Input, Segmented, Select, SubTabs } from "../components/ui";

type View = "gate" | "activity";

// ── Date range gadget ────────────────────────────────────────────────────────
// Predefined sliding windows + a custom from/to picker. Bounds are computed at
// fetch time so presets stay anchored to "now" while the screen live-polls.
type RangePreset = "1h" | "today" | "7d" | "30d" | "all" | "custom";

const RANGE_OPTIONS: { value: RangePreset; label: string }[] = [
  { value: "1h", label: "1h" },
  { value: "today", label: "Today" },
  { value: "7d", label: "7d" },
  { value: "30d", label: "30d" },
  { value: "all", label: "All" },
  { value: "custom", label: "Custom" },
];

interface RangeState {
  preset: RangePreset;
  from: string; // yyyy-mm-dd, custom only
  to: string;
}

function rangeBounds(r: RangeState): { from?: number; to?: number } {
  const now = Math.floor(Date.now() / 1000);
  switch (r.preset) {
    case "1h":
      return { from: now - 3600 };
    case "today": {
      const d = new Date();
      d.setHours(0, 0, 0, 0);
      return { from: Math.floor(d.getTime() / 1000) };
    }
    case "7d":
      return { from: now - 7 * 86400 };
    case "30d":
      return { from: now - 30 * 86400 };
    case "all":
      return {};
    case "custom": {
      const from = r.from
        ? Math.floor(new Date(`${r.from}T00:00:00`).getTime() / 1000)
        : undefined;
      const to = r.to
        ? Math.floor(new Date(`${r.to}T23:59:59`).getTime() / 1000)
        : undefined;
      return { from, to };
    }
  }
}

function RangeBar({
  range,
  setRange,
}: {
  range: RangeState;
  setRange: (r: RangeState) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Segmented
        value={range.preset}
        options={RANGE_OPTIONS}
        onChange={(preset) => setRange({ ...range, preset })}
      />
      {range.preset === "custom" && (
        <>
          <Input
            type="date"
            className="w-38"
            value={range.from}
            onChange={(e) => setRange({ ...range, from: e.target.value })}
          />
          <span className="text-xs text-content-muted">→</span>
          <Input
            type="date"
            className="w-38"
            value={range.to}
            onChange={(e) => setRange({ ...range, to: e.target.value })}
          />
        </>
      )}
    </div>
  );
}

// ── Column definitions ───────────────────────────────────────────────────────

const timeCell = (unix: number | null) => (
  <span className="whitespace-nowrap font-mono text-xs text-content-muted">
    {fullTime(unix)}
  </span>
);

const gateColumns: ColumnDef<AuditEvent, any>[] = [
  {
    header: "Time",
    accessorKey: "unix",
    cell: (c) => timeCell(c.row.original.unix),
    sortDescFirst: true,
  },
  {
    header: "Decision",
    accessorKey: "decision",
    cell: (c) => (
      <Badge tone={decisionTone(c.row.original.decision)}>
        {c.row.original.decision.toUpperCase()}
      </Badge>
    ),
  },
  {
    header: "Secret",
    accessorKey: "secret",
    cell: (c) => <span className="font-medium">{c.row.original.secret || "—"}</span>,
  },
  { header: "Scope", accessorKey: "scope" },
  { header: "Tier", accessorKey: "tier" },
  { header: "Caller", accessorKey: "caller" },
  {
    header: "UID",
    accessorKey: "peer_uid",
    cell: (c) => c.row.original.peer_uid ?? "—",
  },
  {
    header: "Source",
    accessorKey: "source",
    cell: (c) => (
      <span className="text-content-muted">
        {sourceLabel(c.row.original.source)}
      </span>
    ),
  },
  {
    header: "Details",
    accessorKey: "reason",
    enableSorting: false,
    cell: (c) => {
      const e = c.row.original;
      const text = [e.rule, e.reason].filter(Boolean).join(" · ");
      return (
        <span
          className="block max-w-72 truncate text-xs text-content-muted"
          title={text}
        >
          {text || "—"}
        </span>
      );
    },
  },
];

const activityColumns: ColumnDef<ActivityEvent, any>[] = [
  {
    header: "Time",
    accessorKey: "unix",
    cell: (c) => timeCell(c.row.original.unix),
    sortDescFirst: true,
  },
  {
    header: "Action",
    accessorKey: "action",
    cell: (c) => (
      <Badge tone={c.row.original.actor === "agent" ? "judge" : "neutral"}>
        {c.row.original.action}
      </Badge>
    ),
  },
  {
    header: "Target",
    accessorKey: "target",
    cell: (c) => (
      <span className="font-medium">{c.row.original.target ?? "—"}</span>
    ),
  },
  {
    header: "Where",
    accessorKey: "vault",
    cell: (c) => (
      <span className="text-content-muted">{c.row.original.vault}</span>
    ),
  },
  {
    header: "Actor",
    accessorKey: "actor_id",
    cell: (c) => (
      <span className="text-content-muted">{c.row.original.actor_id}</span>
    ),
  },
  {
    header: "Source",
    accessorKey: "source",
    cell: (c) => (
      <span className="text-content-muted">
        {sourceLabel(c.row.original.source)}
      </span>
    ),
  },
];

// Screen 08 — audit. Two views: gate decisions (the policy/judge verdicts on
// agent requests) and the activity timeline (every human/agent action,
// including global provider/judge/MCP config changes). Live-polls; the date
// range applies to both views; each table sorts, quick-searches, and paginates.
export default function Audit() {
  const [view, setView] = useState<View>("gate");
  const [result, setResult] = useState("all");
  const [vault, setVault] = useState("");
  const [caller, setCaller] = useState("");
  const [range, setRange] = useState<RangeState>({
    preset: "7d",
    from: "",
    to: "",
  });

  const vaults = useQuery({ queryKey: ["vaults"], queryFn: listVaults });
  const callers = useQuery({ queryKey: ["audit-callers"], queryFn: auditCallers });

  const events = useQuery({
    queryKey: ["audit", result, vault, caller, range],
    queryFn: () =>
      auditEvents({ result, vault, caller, limit: 5000, ...rangeBounds(range) }),
    refetchInterval: 1500,
    enabled: view === "gate",
  });
  const activity = useQuery({
    queryKey: ["activity", range],
    queryFn: () => {
      const b = rangeBounds(range);
      return activityEvents(5000, b.from, b.to);
    },
    refetchInterval: 1500,
    enabled: view === "activity",
  });

  const gateData = useMemo(() => events.data ?? [], [events.data]);
  const activityData = useMemo(() => activity.data ?? [], [activity.data]);

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
        view === "gate" ? (
          <Button variant="secondary" disabled={!vault} onClick={onExport}>
            Export log
          </Button>
        ) : undefined
      }
    >
      <SubTabs
        value={view}
        onChange={setView}
        tabs={[
          { value: "gate", label: "Gate decisions" },
          { value: "activity", label: "Activity" },
        ]}
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <RangeBar range={range} setRange={setRange} />
        {view === "gate" && (
          <>
            <div className="mx-1 h-6 w-px bg-border-subtle" />
            <Select className="w-32" value={result} onChange={(e) => setResult(e.target.value)}>
              <option value="all">All</option>
              <option value="allowed">Allowed</option>
              <option value="denied">Denied</option>
              <option value="judge">Judge</option>
            </Select>
            <Select className="w-40" value={vault} onChange={(e) => setVault(e.target.value)}>
              <option value="">All vaults</option>
              {(vaults.data ?? []).map((v) => (
                <option key={v.leaf} value={v.leaf}>
                  {v.name}
                </option>
              ))}
            </Select>
            <Select className="w-40" value={caller} onChange={(e) => setCaller(e.target.value)}>
              <option value="">All callers</option>
              {(callers.data ?? []).map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </Select>
          </>
        )}
      </div>

      {view === "gate" && (
        <DataTable
          columns={gateColumns}
          data={gateData}
          searchPlaceholder="Search secret, caller, rule…"
          initialSort={[{ id: "unix", desc: true }]}
          emptyMessage="No gate decisions in this range."
        />
      )}

      {view === "activity" && (
        <DataTable
          columns={activityColumns}
          data={activityData}
          searchPlaceholder="Search action, target, actor…"
          initialSort={[{ id: "unix", desc: true }]}
          emptyMessage="No activity in this range."
        />
      )}
    </Page>
  );
}

export function decisionTone(decision: string): "allow" | "deny" | "pending" {
  if (decision === "allow") return "allow";
  if (decision === "deny") return "deny";
  return "pending";
}

// Compact card row — still used by the MCP live log.
export function EventRow({ e }: { e: AuditEvent }) {
  return (
    <Card className="p-3 text-sm">
      <div className="flex items-center gap-2">
        <Badge tone={decisionTone(e.decision)}>{e.decision.toUpperCase()}</Badge>
        <span className="font-medium">{e.secret || "—"}</span>
        {e.scope && <Badge tone="neutral">{e.scope}</Badge>}
        {e.tier && <Badge tone="neutral">{e.tier}</Badge>}
        <span className="ml-auto font-mono text-xs text-content-muted">
          {sourceLabel(e.source)} · {fullTime(e.unix)}
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
