import * as Sentry from "@sentry/react";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { appLogDir, join } from "@tauri-apps/api/path";

// Initialize Sentry
export function initSentry() {
  const dsn = import.meta.env.VITE_SENTRY_DSN;

  if (!dsn) {
    console.warn("Sentry DSN not found. Error tracking disabled.");
    return;
  }

  Sentry.init({
    dsn,
    environment: import.meta.env.MODE,
    release: import.meta.env.VITE_APP_VERSION || "0.1.5",
    // Minimal config; tracing disabled to avoid extra dependencies
    beforeSend(event) {
      try {
        const line = JSON.stringify({ ts: new Date().toISOString(), sentry: event }) + "\n";
        // Resolve app log directory and append line
        appLogDir().then((dir) => {
          join(dir, "app.log").then((path) => {
            writeTextFile(path, line, { append: true } as any).catch(() => {});
          });
        });
      } catch (_) {}
      return event;
    },
  });
}

// Export Sentry for manual error reporting
export { Sentry };
