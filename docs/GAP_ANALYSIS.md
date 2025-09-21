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

- Tauri background loop (15 min) fetches config, runs bundled `osqueryi`, and posts data to API.
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
  - On 401 from the API, Tauri emits `auth:invalidated` and updates `auth:status`

#### 2) Loop A: Config → osquery → Local Store (SQLite)

- Expected: Results are written to a local SQLite queue every cycle.
- Current: Results are posted immediately; no local persistence.
- Gaps: No SQLite database/schema for results and metadata.
- Recommendations:
  - Add SQLite via `tauri-plugin-sql` with schema, e.g.:
    - `results(id INTEGER PK, table TEXT, json TEXT, created_at DATETIME, handled BOOLEAN DEFAULT 0, handled_at DATETIME NULL)`
    - `metadata(key TEXT PK, value TEXT)` (store `last_upload_at`)
  - Insert all osquery rows as unhandled on each cycle

#### 3) Loop B: Upload Pending → Mark Handled → Update last_upload_at

- Expected: Every cycle, select pending rows (`handled=false` and `created_at > last_upload_at`), POST, mark handled, update `last_upload_at`.
- Current: Immediate POST after collection only; no pending queue; no `last_upload_at`.
- Gaps: No durability, idempotency, partial-batch handling, or retry/backoff.
- Recommendations:
  - Implement a separate uploader that drains batches from SQLite, marks handled in a transaction, and sets `metadata.last_upload_at=now()`
  - Add exponential backoff on transient failures; never drop data

#### 4) Background Execution and System Sleep

- Expected: Runs without UI; robust to sleep/wake.
- Current: Runs in Tauri without UI; during sleep, timers pause and resume on wake.
- Gaps: Without a queue, missed data can be lost; no explicit backlog drain strategy.
- Recommendations: Rely on SQLite queue and drain backlog on wake/start; optionally assert power during active runs (advanced macOS) if necessary.

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

### Summary of Required Changes

- Secure, durable Tauri token storage (Keychain) and boot-time restore; Tauri authoritative for auth state
- Introduce SQLite queue (`results`, `metadata.last_upload_at`); separate uploader with mark-as-handled and retry/backoff
- First-class environment setup via `.env.*` (dev/staging/prod) for both API and Earthenware; optional `VITE_ENVIRONMENT`
- Keep data loops fully within Tauri; React limited to authentication UX and optional display
- Accept OS sleep; ensure backlog drain on wake/start
- Keep LaunchAgent autostart; optionally add `StartInterval`; restrict CI to Apple Silicon
