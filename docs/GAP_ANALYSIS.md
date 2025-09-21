## KlaayGuard authentication, data collection, and upload sequence

The following sequence diagram documents the startup authentication check, followed by two 15-minute loops: (A) config fetch → osquery run → local store, and (B) upload pending data → mark handled. All API requests include the authentication token once obtained.

```mermaid
sequenceDiagram
    autonumber
    participant Agent as KlaayGuard Agent
    participant API as Kiln API
    participant Iframe as Earthenware Login (iframe)
    participant Osquery as osquery
    participant SQLite as SQLite DB

    %% Startup authentication check
    Agent->>API: GET /me
    alt 200 OK (authenticated)
        API-->>Agent: 200 OK<br/>User info
        Agent->>Agent: Ensure token available
    else Not authenticated
        API-->>Agent: 401/403/other
        Agent->>Iframe: Render login form
        Iframe-->>Agent: Login success<br/>auth token
        Agent->>Agent: Store token securely
    end

    Note over Agent,API: All API requests include Authorization: Bearer <token>

    par Loop A: Data Collection
        loop Every 15 minutes
            Agent->>API: GET /klaayguard/config<br/>Authorization: Bearer <token>
            API-->>Agent: 200 OK<br/>Config JSON
            Agent->>Osquery: Run with Config
            Osquery-->>Agent: Result rows
            Agent->>SQLite: INSERT result rows
        end
    and Loop B: Data Upload
        loop Every 15 minutes
            Agent->>SQLite: SELECT rows WHERE handled=false<br/>AND created_at > last_upload_at
            SQLite-->>Agent: Pending rows
            Agent->>API: POST /klaayguard/data<br/>(pending rows)<br/>Authorization: Bearer <token>
            API-->>Agent: 202 Accepted
            Agent->>SQLite: UPDATE rows SET handled=true, handled_at=now()
            Agent->>SQLite: UPDATE metadata SET last_upload_at=now()
        end
    end
```

---

## Gap Analysis and Implementation Guidance

### Assumptions and Environment Targets

- React app is only for authentication (Earthenware iframe) and optional user display.
- Background data collection and upload run in Tauri irrespective of the React window.
- App must auto-start at login and keep running if closed; recover after restarts.
- Target platform (for now): macOS Apple Silicon.
- Environments and endpoints:
  - **Development**: API `http://localhost:3000`, Earthenware `http://localhost:5173`
  - **Staging**: API `https://api.klaay.dev`, Earthenware `https://app.klaay.dev`
  - **Production**: API `https://api.klaay.com`, Earthenware `https://app.klaay.com`

### Current Implementation Snapshot

- Loop A: Tauri background loop (15 min) fetches config, runs bundled `osqueryi`, and persists results to a local SQLite queue (`results` table).
- Loop B: Background uploader implemented. Drains pending rows and advances a `last_upload_at` watermark in `metadata` after successful upload.
- macOS LaunchAgent installed with `RunAtLoad` and `KeepAlive=true`; window close hides; no quit menu; duplicate instance guard; updater enabled.
- React handles iframe login and `/authenticate` POST; the iframe posts the token directly to Tauri via IPC. Tauri stores the token securely in the macOS Keychain and restores it on boot. React does not persist or read the token and instead uses a tokenless `get_auth_status` IPC.
- Endpoints provided via `VITE_API_BASE_URL` and `VITE_EARTHENWARE_URL` (used by both React and Tauri).

### Gaps and Recommendations

#### 1) Authentication and Token Management

- Status: Implemented
  - Tauri is authoritative for the auth token and stores it in the macOS Keychain
  - Token is restored at boot before background loops start
  - IPC commands: `save_auth_token`, `clear_auth_token`, `get_auth_status` (returns `{ authenticated, display_name }` without exposing the token)
  - React never persists or reads the token; the Earthenware iframe posts the token to Tauri via IPC
  - Iframe origin check uses `new URL(VITE_EARTHENWARE_URL).origin` against `event.origin`
- On 401/403 from the API, Tauri clears the token, emits `auth:invalidated`, updates `auth:status`, and brings the app window to the foreground for re‑login

#### 2) Loop A: Config → osquery → Local Store (SQLite)

- Status: Implemented
  - On each cycle, the agent GETs `/klaayguard/config` with the bearer token, runs `osqueryi` accordingly, and inserts all rows into SQLite `results` with fields: `id`, `table_name`, `json`, `run_id`, `created_at`, `handled`, `handled_at`.
  - A `run_id` (UUID) groups all rows generated in a single execution.
  - DB mode: file‑backed by default in development at `~/Library/Application Support/com.klaay.app/klaayguard.db`; optional memory mode via `KLAAYGUARD_DB_MODE=memory`.
  - Non‑overlapping 15‑minute scheduler; emits `collection:success` with `{ run_id, inserted_rows }`.
  - On 401/403 during config fetch, the token is cleared and the app focuses for re‑login (cycle aborts).

#### 3) Loop B: Upload Pending → Mark Handled → Update last_upload_at

- Status: Implemented

  - Separate uploader task with immediate drain on startup and a 15‑minute interval (`KLAAYGUARD_UPLOAD_INTERVAL_SECONDS`), guarded to avoid overlap.
  - Selects pending rows with `handled = false AND created_at > last_upload_at`, ordered by `created_at` asc, limited by `KLAAYGUARD_UPLOAD_MAX_ROWS` (default 1000).
  - POSTs to `POST /klaayguard/data` with `Authorization: Bearer <token>` and payload `{ device_id, batch_id, rows[] }` where each row includes `id, table_name, json, run_id, created_at`.
  - On `202 Accepted` (or generally success), marks posted rows `handled=true, handled_at=now()` and advances `metadata.last_upload_at` to `MAX(created_at)` of the handled set in a single transaction.
  - Emits UI events: `upload:success` on success; `upload:error` with `{ stage, status }` on errors.
  - On `401/403`, clears token from Keychain, emits `auth:invalidated` and `auth:status`, and focuses/shows the app for re‑login. No rows are marked in this case.

- Remaining gaps / enhancements:
  - Payload size cap and payload splitting by bytes (currently only row‑count cap).
  - Rate‑limit and transient error exponential backoff with jitter (currently retries next interval).
  - Optional per‑row acceptance handling if server returns granular statuses (currently marks all on success).
  - Wake‑from‑sleep trigger to drain immediately (startup immediate drain is implemented).

#### 4) Background Execution and System Sleep

- Status: Running headless in Tauri; Loop A and Loop B both operate without UI.
- Startup: Immediate drain for Loop B implemented to catch up backlog.
- Sleep/Wake: Timers pause during sleep and resume on wake; backlog persists in SQLite and drains on next interval. Optional wake trigger for immediate drain remains a possible enhancement.

#### 5) Environment Management (Dev/Staging/Prod)

- Expected: Distinct API and Earthenware URLs per environment; both layers aligned.
- Current: Uses `VITE_API_BASE_URL` and `VITE_EARTHENWARE_URL`; no central environment switch or validation.
- Gaps: Possible mismatch between React and Tauri if env vars diverge.
- Recommendations: Provide `.env.development`, `.env.staging`, `.env.production`; optionally add `VITE_ENVIRONMENT`; expose active URLs from Tauri to React and warn if mismatched.

#### 6) Tauri Autostart and Process Management

- Expected: Auto-start and keep running; lean on native mechanisms.
- Current: LaunchAgent (`RunAtLoad`, `KeepAlive=true`), hide-on-close, no Quit menu, duplicate-instance guard, updater.
- Gaps: None critical; optional use of `tauri-plugin-autostart` if cross-platform needed.
- Recommendations: Keep LaunchAgent; optionally add `StartInterval` as a safety net; continue using in-process tokio interval for 15-minute cadence.

#### 7) Apple Silicon Targeting

- Expected: Build for macOS Apple Silicon only (for now).
- Current: Bundled `osqueryi` and generic targets; CI may build wider.
- Gaps: Ensure release targeting is restricted in CI and binary matches architecture.
- Recommendations: Gate CI to `aarch64-apple-darwin`; validate bundled `osqueryi`.

#### 8) Security and Robustness Notes

- Token exposure: Prefer Keychain persistence and avoid re-exposing raw token to React; expose `authenticated` flag and display info.
- Iframe origin checks: Compare `new URL(VITE_EARTHENWARE_URL).origin` with `event.origin` to avoid subtle mismatches.
- Observability: Add structured logs and Sentry breadcrumbs in Tauri for config/collect/upload stages, including status codes and retry counts.

### Status Summary & Next Steps

- Authentication storage/restore implemented; 401/403 invalidation clears token and focuses app for re‑login.
- Loop A and Loop B implemented end‑to‑end. `metadata.last_upload_at` advances to the handled set’s max `created_at` on success.
- Next enhancements: payload size cap/splitting, explicit exponential backoff with jitter and `Retry‑After` support, optional per‑row result handling, and wake‑triggered immediate drain.
- Ensure `.env.*` alignment for API/Earthenware; keep loops and auth strictly in Tauri. LaunchAgent and Apple Silicon targeting unchanged.
