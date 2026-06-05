// Format a countdown to a unix-seconds deadline as "1h 23m" / "4m 12s" / "—".
export function countdownTo(deadlineUnix: number | null): string {
  if (deadlineUnix == null) return "—";
  const secs = deadlineUnix - Math.floor(Date.now() / 1000);
  if (secs <= 0) return "expired";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// Format a raw seconds-remaining value as "1h 23m" / "4m 12s".
export function formatSecs(secs: number | null | undefined): string {
  if (secs == null) return "—";
  if (secs <= 0) return "now";
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// Format a unix-seconds timestamp as a short local time / date.
export function shortTime(unix: number | null | undefined): string {
  if (unix == null) return "—";
  const d = new Date(unix * 1000);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}

// Human label for an audit/usage `source` code. The logs store the short code;
// the UI shows what a person would call it.
export function sourceLabel(source: string): string {
  switch (source) {
    case "gui":
      return "Desktop app";
    case "cli":
      return "CLI";
    case "tui":
      return "Terminal UI";
    case "mcp":
      return "MCP (agent)";
    default:
      return source;
  }
}

// Full timestamp for audit rows: "Jun 6, 14:32:05" (year added when not this year).
export function fullTime(unix: number | null | undefined): string {
  if (unix == null) return "—";
  const d = new Date(unix * 1000);
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return (
    d.toLocaleDateString([], {
      month: "short",
      day: "numeric",
      ...(sameYear ? {} : { year: "numeric" }),
    }) +
    ", " +
    d.toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    })
  );
}
