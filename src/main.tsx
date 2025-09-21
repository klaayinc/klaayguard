import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import "swiper/swiper-bundle.css";
import "simplebar-react/dist/simplebar.min.css";
import App from "./App.tsx";
import { AppWrapper } from "./components/common/PageMeta.tsx";
import { ThemeProvider } from "./context/ThemeContext.tsx";
import { initSentry } from "./sentry.ts";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { appLogDir, join } from "@tauri-apps/api/path";

// Initialize Sentry before rendering the app
initSentry();

// Minimal client-side file logger for runtime errors
window.addEventListener("error", (e) => {
  try {
    const payload = { ts: new Date().toISOString(), type: "error", message: e.message, filename: e.filename, lineno: e.lineno, colno: e.colno, stack: e.error?.stack };
    appLogDir().then((dir) => {
      join(dir, "app.log").then((path) => {
        writeTextFile(path, JSON.stringify(payload) + "\n", { append: true } as any).catch(() => {});
      });
    });
  } catch (_) {}
});
window.addEventListener("unhandledrejection", (e) => {
  try {
    const payload = { ts: new Date().toISOString(), type: "unhandledrejection", reason: String((e as any).reason || "unknown") };
    appLogDir().then((dir) => {
      join(dir, "app.log").then((path) => {
        writeTextFile(path, JSON.stringify(payload) + "\n", { append: true } as any).catch(() => {});
      });
    });
  } catch (_) {}
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider>
      <AppWrapper>
        <App />
      </AppWrapper>
    </ThemeProvider>
  </StrictMode>
);
