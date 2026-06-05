import { useQuery } from "@tanstack/react-query";
import { sessionStatus } from "./api";

// Session/daemon status, polled once a second so the daemon block's countdown
// ticks and the unlocked-vault set stays live. Screens and the shell share this
// one query.
export function useSessionStatus() {
  return useQuery({
    queryKey: ["session-status"],
    queryFn: sessionStatus,
    refetchInterval: 1000,
  });
}
