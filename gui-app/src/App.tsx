import { useEffect, useState } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import { useSessionStatus } from "./lib/hooks";
import { useSession } from "./store/session";
import { AppShell } from "./components/shell";
import SignIn from "./screens/SignIn";
import Onboarding from "./screens/Onboarding";
import Vaults from "./screens/Vaults";
import VaultConfig from "./screens/VaultConfig";
import Secrets from "./screens/Secrets";
import Judges from "./screens/Judges";
import Mcp from "./screens/Mcp";
import Pending from "./screens/Pending";
import Audit from "./screens/Audit";
import Backup from "./screens/Backup";
import Settings from "./screens/Settings";
import Recover from "./screens/Recover";

export default function App() {
  return (
    <HashRouter>
      <Gate />
    </HashRouter>
  );
}

// Decides which top-level flow renders: first-run onboarding, the locked
// sign-in gate, or the full app shell once signed in.
function Gate() {
  const { data: status, isLoading } = useSessionStatus();
  const signedIn = useSession((s) => s.signedIn);

  // Latch onboarding: once we see there's no master, stay in the onboarding flow
  // until it completes (which signs the user in). Without this, the moment step 2
  // creates the master, the live `master_exists` poll would flip and tear down
  // the stepper — skipping the one-time recovery code and the YubiKey step.
  const [onboarding, setOnboarding] = useState(false);
  useEffect(() => {
    if (status && !status.master_exists) setOnboarding(true);
  }, [status]);

  if (isLoading || !status) {
    return (
      <div className="flex h-full items-center justify-center text-content-muted">
        Loading…
      </div>
    );
  }

  // Onboarding runs to completion; finishing it calls signIn() → app shell.
  if (onboarding && !signedIn) {
    return (
      <Routes>
        <Route path="*" element={<Onboarding />} />
      </Routes>
    );
  }

  if (!status.master_exists) {
    return (
      <Routes>
        <Route path="*" element={<Onboarding />} />
      </Routes>
    );
  }

  if (!signedIn) {
    return (
      <Routes>
        <Route path="/recover" element={<Recover />} />
        <Route path="*" element={<SignIn />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/vaults" replace />} />
        <Route path="/vaults" element={<Vaults />} />
        <Route path="/vaults/new" element={<VaultConfig />} />
        <Route path="/vaults/:leaf" element={<Secrets />} />
        <Route path="/vaults/:leaf/settings" element={<VaultConfig />} />
        <Route path="/judges" element={<Judges />} />
        <Route path="/mcp" element={<Mcp />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/pending" element={<Pending />} />
        <Route path="/backup" element={<Backup />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/vaults" replace />} />
      </Route>
    </Routes>
  );
}
