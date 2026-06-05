import { useQuery } from "@tanstack/react-query";
import { keyringState, sessionStatus } from "./api";

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

// Whether an AI judge is actually active (global switch on + at least one
// defined). Vault and secret screens hide their judge options until then —
// no dangling "assign a judge" fields when there is nothing to assign.
export function useJudgeActive() {
  const { data } = useQuery({
    queryKey: ["keyring-state"],
    queryFn: keyringState,
  });
  return (data?.judge_enabled ?? false) && (data?.judge_count ?? 0) > 0;
}
