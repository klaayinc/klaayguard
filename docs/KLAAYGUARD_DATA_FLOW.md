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
