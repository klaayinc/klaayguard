
import React, { createContext, useState, useContext, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";


type AuthContextType = {
  isAuthenticated: boolean;
  error: string;
  userName: string | null;
  checkAuthentication: () => void;
  logout: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const navigate = useNavigate();
  const [error, setError] = useState<string>("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userName, setUserName] = useState<string | null>(null);

  // No longer check first launch or handle osquery installation

  // Name is retrieved from Tauri via get_auth_status; no direct token use in React

  async function checkAuthentication() {
    try {
      const status = await invoke<{ authenticated: boolean; display_name: string | null }>("get_auth_status");
      setIsAuthenticated(!!status.authenticated);
      if (status.display_name) setUserName(status.display_name);
      setError("");
    } catch {
      setIsAuthenticated(false);
      setError("An error occurred during authentication.");
    }
  }

  // Token decoding removed; React should not inspect the token

  // React no longer performs username/password authentication; Earthenware iframe posts token to Tauri

  useEffect(() => {
    const initializeApp = async () => {
      const currentPath = window.location.pathname;
      try {
        const status = await invoke<{ authenticated: boolean; display_name: string | null }>("get_auth_status");
        if (status.authenticated) {
          setIsAuthenticated(true);
          if (status.display_name) setUserName(status.display_name);
          if (currentPath === "/signin") navigate("/welcome");
        } else {
          setIsAuthenticated(false);
          navigate("/signin");
        }
      } catch {
        navigate("/signin");
      }
    };

    initializeApp();
  }, []);

  // Removed localStorage listener; iframe now sends token directly to Tauri

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let unlistenStatus: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen("auth:invalidated", () => {
          logout();
        });
      } catch {
        // ignore
      }
      try {
        unlistenStatus = await listen("auth:status", async (event) => {
          const payload = (event as unknown as { payload?: { authenticated?: boolean } }).payload;
          const authenticated = !!(payload && payload.authenticated);
          setIsAuthenticated(authenticated);
          if (authenticated) {
            try {
              const status = await invoke<{ authenticated: boolean; display_name: string | null }>("get_auth_status");
              if (status.display_name) setUserName(status.display_name);
            } catch {
              // ignore name fetch
            }
            navigate("/welcome");
          } else {
            navigate("/signin");
          }
        });
      } catch {
        // ignore
      }
    })();

    return () => {
      if (unlisten) {
        try { unlisten(); } catch { /* noop */ }
      }
      if (unlistenStatus) {
        try { unlistenStatus(); } catch { /* noop */ }
      }
    };
  }, []);

  // No token-driven side effects in React

  const logout = () => {
    setIsAuthenticated(false);
    try {
      void invoke("clear_auth_token");
    } catch (_e) {
      // ignore
    }
    navigate("/signin");
  };

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        error,
        userName,
        checkAuthentication,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
