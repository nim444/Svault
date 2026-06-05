import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  changeMaster,
  daemonDoctor,
  daemonInfo,
  daemonStart,
  daemonStop,
  diagnostics,
  enrollYubikey,
  getPrefs,
  installCli,
  lockAll,
  removeYubikey,
  setDaemonLimits,
  setPrefs,
  yubikeyStatus,
} from "../lib/api";
import { Page } from "../components/shell";
import {
  Button,
  Card,
  Field,
  Input,
  Select,
  SubTabs,
  Toggle,
} from "../components/ui";

type Tab = "appearance" | "security" | "diagnostics";

export default function Settings() {
  const [tab, setTab] = useState<Tab>("appearance");
  return (
    <Page title="Settings">
      <SubTabs
        value={tab}
        onChange={setTab}
        tabs={[
          { value: "appearance", label: "Appearance & startup" },
          { value: "security", label: "Security & daemon" },
          { value: "diagnostics", label: "Diagnostics" },
        ]}
      />
      {tab === "appearance" && <AppearanceTab />}
      {tab === "security" && <SecurityTab />}
      {tab === "diagnostics" && <DiagnosticsTab />}
    </Page>
  );
}

function AppearanceTab() {
  const prefs = useQuery({ queryKey: ["prefs"], queryFn: getPrefs });
  const qc = useQueryClient();
  const [local, setLocal] = useState<Record<string, unknown>>({});
  useEffect(() => {
    if (prefs.data) setLocal(prefs.data);
  }, [prefs.data]);

  const saveM = useMutation({
    mutationFn: (next: Record<string, unknown>) => setPrefs(next),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["prefs"] }),
  });
  function update(key: string, value: unknown) {
    const next = { ...local, [key]: value };
    setLocal(next);
    saveM.mutate(next);
  }

  return (
    <Card className="max-w-xl p-5">
      <div className="flex flex-col gap-4">
        <Field label="Theme">
          <Select
            className="w-48"
            value={String(local.theme ?? "system")}
            onChange={(e) => update("theme", e.target.value)}
          >
            <option value="system">System</option>
            <option value="dark">Dark</option>
            <option value="light">Light</option>
            <option value="hicontrast">Hi-contrast</option>
          </Select>
        </Field>
        <Toggle
          checked={Boolean(local.reduce_motion)}
          onChange={(v) => update("reduce_motion", v)}
          label="Reduce motion"
        />
        <Toggle
          checked={Boolean(local.show_tray ?? true)}
          onChange={(v) => update("show_tray", v)}
          label="Show in menu bar / system tray"
        />
        <Toggle
          checked={Boolean(local.launch_at_login)}
          onChange={(v) => update("launch_at_login", v)}
          label="Launch at login"
        />
        <Toggle
          checked={Boolean(local.close_to_tray ?? true)}
          onChange={(v) => update("close_to_tray", v)}
          label="Close to tray"
        />
        <p className="text-xs text-content-muted">
          Preferences are saved instantly. Tray and launch-at-login take effect on
          the next app start.
        </p>
      </div>
    </Card>
  );
}

function SecurityTab() {
  const qc = useQueryClient();
  const yk = useQuery({ queryKey: ["yubikey"], queryFn: yubikeyStatus });
  const daemon = useQuery({
    queryKey: ["daemon-info"],
    queryFn: daemonInfo,
    refetchInterval: 2000,
  });

  const [pp, setPp] = useState("");
  const [pp2, setPp2] = useState("");
  const [pin, setPin] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [idle, setIdle] = useState<number | null>(null);
  const [maxc, setMaxc] = useState<number | null>(null);

  useEffect(() => {
    if (daemon.data) {
      if (idle == null) setIdle(Math.round(daemon.data.idle_timeout_secs / 60));
      if (maxc == null) setMaxc(daemon.data.max_connections);
    }
  }, [daemon.data]);

  const rekeyM = useMutation({
    mutationFn: () => changeMaster(pp),
    onSuccess: () => {
      setStatus("Master passphrase changed.");
      setPp("");
      setPp2("");
    },
    onError: (e) => setStatus(String(e)),
  });
  const enrollM = useMutation({
    mutationFn: () => enrollYubikey(pin || null),
    onSuccess: () => {
      setStatus("YubiKey enrolled.");
      setPin("");
      qc.invalidateQueries({ queryKey: ["yubikey"] });
    },
    onError: (e) => setStatus(String(e)),
  });
  const removeYkM = useMutation({
    mutationFn: removeYubikey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["yubikey"] }),
  });
  const startM = useMutation({ mutationFn: daemonStart, onSuccess: () => daemon.refetch() });
  const stopM = useMutation({ mutationFn: daemonStop, onSuccess: () => daemon.refetch() });
  const doctorM = useMutation({ mutationFn: daemonDoctor, onSuccess: () => daemon.refetch() });
  const limitsM = useMutation({
    mutationFn: () => setDaemonLimits((idle ?? 15) * 60, maxc ?? 512),
    onSuccess: () => setStatus("Daemon limits saved (apply on next start)."),
  });

  return (
    <div className="grid max-w-3xl grid-cols-2 gap-4">
      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Master & keys</h3>
        <div className="flex flex-col gap-3">
          <Field label="New master passphrase">
            <Input type="password" value={pp} onChange={(e) => setPp(e.target.value)} />
          </Field>
          <Field label="Confirm">
            <Input type="password" value={pp2} onChange={(e) => setPp2(e.target.value)} />
          </Field>
          <Button
            disabled={!pp || pp !== pp2 || rekeyM.isPending}
            onClick={() => rekeyM.mutate()}
          >
            Change passphrase
          </Button>
          <div className="border-t border-border-subtle pt-3 text-sm">
            <div className="mb-2 text-content-muted">
              YubiKey: {yk.data?.enrolled ? "enrolled" : "not enrolled"} ·{" "}
              {yk.data?.present ? "connected" : "not connected"}
            </div>
            {yk.data?.enrolled ? (
              <Button variant="secondary" onClick={() => removeYkM.mutate()}>
                Remove YubiKey
              </Button>
            ) : (
              <div className="flex gap-2">
                <Input
                  type="password"
                  placeholder="PIN (blank if none)"
                  value={pin}
                  onChange={(e) => setPin(e.target.value)}
                />
                <Button disabled={!yk.data?.present || enrollM.isPending} onClick={() => enrollM.mutate()}>
                  Enroll
                </Button>
              </div>
            )}
          </div>
          <div className="border-t border-border-subtle pt-3">
            <Row k="Re-auth cap" v="6h (fixed)" />
            <Button variant="secondary" className="mt-2" onClick={() => lockAll()}>
              Lock all
            </Button>
          </div>
        </div>
      </Card>

      <Card className="p-4">
        <h3 className="mb-3 text-sm font-semibold">Daemon</h3>
        {daemon.data?.supported === false ? (
          <p className="text-sm text-content-muted">
            This platform has no daemon — Svault uses the 0600 session fallback.
          </p>
        ) : (
          <div className="flex flex-col gap-3 text-sm">
            <Row k="Status" v={daemon.data?.running ? "running" : "stopped"} />
            <Row k="PID" v={daemon.data?.pid ? String(daemon.data.pid) : "—"} />
            <div className="flex gap-2">
              {daemon.data?.running ? (
                <Button variant="secondary" onClick={() => stopM.mutate()}>
                  Stop
                </Button>
              ) : (
                <Button variant="secondary" onClick={() => startM.mutate()}>
                  Start
                </Button>
              )}
              <Button variant="secondary" onClick={() => doctorM.mutate()}>
                Run doctor
              </Button>
            </div>
            <Field label="Auto-lock idle (minutes)">
              <Input
                type="number"
                value={idle ?? ""}
                onChange={(e) => setIdle(Number(e.target.value))}
              />
            </Field>
            <Field label="Max connections">
              <Input
                type="number"
                value={maxc ?? ""}
                onChange={(e) => setMaxc(Number(e.target.value))}
              />
            </Field>
            <Button onClick={() => limitsM.mutate()}>Save daemon limits</Button>
          </div>
        )}
      </Card>

      {status && <p className="col-span-2 text-sm text-content-muted">{status}</p>}
    </div>
  );
}

function DiagnosticsTab() {
  const diag = useQuery({ queryKey: ["diagnostics"], queryFn: diagnostics });
  const [cliStatus, setCliStatus] = useState<string | null>(null);
  const installM = useMutation({
    mutationFn: installCli,
    onSuccess: (p) => setCliStatus(`Installed to ${p}`),
    onError: (e) => setCliStatus(String(e)),
  });
  return (
    <Card className="max-w-xl p-5">
      <h3 className="mb-3 text-sm font-semibold">About & diagnostics</h3>
      <pre className="overflow-auto rounded-lg bg-surface-sunken p-3 text-xs">
        {diag.data ?? "…"}
      </pre>
      <div className="mt-3 flex gap-2">
        <Button variant="secondary" onClick={() => writeText(diag.data ?? "")}>
          Copy diagnostics
        </Button>
        <Button variant="secondary" onClick={() => installM.mutate()}>
          Install CLI to PATH
        </Button>
      </div>
      {cliStatus && <p className="mt-2 text-xs text-content-muted">{cliStatus}</p>}
      <p className="mt-3 text-xs text-content-muted">
        Installing the CLI also provides the TUI and MCP server (`svault mcp`). No
        secrets are included in diagnostics.
      </p>
    </Card>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-4 py-0.5 text-sm">
      <span className="text-content-muted">{k}</span>
      <span>{v}</span>
    </div>
  );
}
