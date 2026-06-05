import { create } from "zustand";

// GUI-session flag. The app always launches locked (signedIn=false); signing in
// requires the master passphrase even if vault keys are still cached in the
// daemon. Sign-out flips this back to false WITHOUT touching the daemon, MCP, or
// vault-unlock state — those are separate, explicit actions.
interface SessionState {
  signedIn: boolean;
  signIn: () => void;
  signOut: () => void;
}

export const useSession = create<SessionState>((set) => ({
  signedIn: false,
  signIn: () => set({ signedIn: true }),
  signOut: () => set({ signedIn: false }),
}));
