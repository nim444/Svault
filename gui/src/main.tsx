import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import TrayPopover from "./screens/TrayPopover";
// IBM Plex Sans — the app's default UI typeface; IBM Plex Mono for data
// (codes, secrets, paths, logs). Bundled via @fontsource so it works offline.
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles.css";
import { initAppearance } from "./lib/theme";

// Apply the saved theme / reduce-motion prefs before first paint settles.
void initAppearance();

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});

// The popover window loads the same bundle; render the compact tray view for it.
const isPopover = getCurrentWindow().label === "popover";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      {isPopover ? <TrayPopover /> : <App />}
    </QueryClientProvider>
  </React.StrictMode>,
);
