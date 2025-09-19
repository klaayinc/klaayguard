import * as Sentry from "@sentry/react";

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
    release: import.meta.env.VITE_APP_VERSION || "0.1.4",
    tracesSampleRate: 1.0,
    integrations: [
      new Sentry.BrowserTracing({
        // Set sampling rate for performance monitoring
        tracePropagationTargets: [
          "localhost",
          /^https:\/\/yourserver\.com\/api/,
        ],
      }),
    ],
    // Capture unhandled promise rejections
    captureUnhandledRejections: true,
    // Capture uncaught exceptions
    beforeSend(event) {
      // Filter out development errors if needed
      if (import.meta.env.MODE === "development") {
        console.log("Sentry event:", event);
      }
      return event;
    },
  });
}

// Export Sentry for manual error reporting
export { Sentry };
