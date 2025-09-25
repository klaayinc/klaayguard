import React from "react";
import { useLocation } from "react-router-dom";

export default function ArchMismatch() {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const built = params.get("built") || "unknown";
  const host = params.get("host") || "unknown";

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 p-6">
      <div className="max-w-md w-full bg-white shadow rounded-lg p-6">
        <h1 className="text-xl font-semibold mb-2">Architecture Mismatch</h1>
        <p className="text-sm text-gray-700 mb-4">
          This app was built for <strong>{built}</strong>, but your machine is <strong>{host}</strong>.
        </p>
        <p className="text-sm text-gray-700 mb-6">
          Please install the correct build of KlaayGuard for your architecture.
        </p>
        <div className="flex items-center gap-3">
          <a
            className="h-10 px-4 rounded bg-black text-white inline-flex items-center"
            href={`${import.meta.env.VITE_EARTHENWARE_URL as string}/employee-hub`}
            onClick={async (e) => {
              e.preventDefault();
              const url = `${import.meta.env.VITE_EARTHENWARE_URL as string}/employee-hub`;
              try {
                const { open } = await import("@tauri-apps/plugin-shell");
                await open(url);
              } catch {
                try { window.open(url, "_blank"); } catch { /* no-op */ }
              }
            }}
          >
            Get Correct Build
          </a>
        </div>
      </div>
    </div>
  );
}


