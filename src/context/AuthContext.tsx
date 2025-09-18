
import React, { createContext, useState, useContext, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import { API_BASE_URL } from "../constants/api";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";


type AuthContextType = {
  token: string | null;
  isAuthenticated: boolean;
  isAccountConfigRequired: boolean;
  error: string;
  userName: string | null;
  checkAuthentication: () => void;
  authenticateUser: (
    username: string,
    password: string,
    accountId: string | undefined
  ) => void;
  logout: () => void;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const navigate = useNavigate();
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string>("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isAccountConfigRequired, setIsAccountConfigRequired] = useState(false);
  const [userName, setUserName] = useState<string | null>(null);

  // No longer check first launch or handle osquery installation

  const fetchUserNameFromMe = async (bearerToken: string): Promise<string | null> => {
    try {
      const resp = await fetch(`${API_BASE_URL}/me`, {
        method: "GET",
        headers: { Authorization: `Bearer ${bearerToken}` },
      });
      if (!resp.ok) return null;
      const body = await resp.json();
      const attrs = body?.data?.attributes ?? {};
      const first = (attrs.first_name as string | undefined) || "";
      const last = (attrs.last_name as string | undefined) || "";
      const email = (attrs.email as string | undefined) || null;
      const full = `${first} ${last}`.trim();
      return full || email || null;
    } catch {
      return null;
    }
  };

  async function checkAuthentication() {
    try {
      const response = await fetch(`${API_BASE_URL}/me`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        setIsAuthenticated(true);
        try {
          if (token) {
            const name = await fetchUserNameFromMe(token);
            if (name) setUserName(name);
          }
        } catch {}
        setError("");
      } else {
        setIsAuthenticated(false);
        setError("Authentication failed. Please check your credentials.");
      }
    } catch (_err) {
      setIsAuthenticated(false);
      setError("An error occurred during authentication.");
    }
  }

  const decodeTokenManually = (token: string) => {
    try {
      const payload = jwtDecode(token);
      return payload;
    } catch (_error) {
      return null;
    }
  };

  async function authenticateUser(
    username: string,
    password: string,
    accountId: string | undefined
  ) {
    try {
      const requestBody = accountId
        ? {
            data: {
              type: "authorization",
              attributes: {
                email: username,
                password: password,
              },
              relationships: {
                account: {
                  data: {
                    type: "account",
                    id: accountId,
                  },
                },
              },
            },
          }
        : {
            data: {
              type: "authorization",
              attributes: {
                email: username,
                password: password,
              },
            },
          };
      const response = await fetch(`${API_BASE_URL}/authenticate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
        },
        body: JSON.stringify(requestBody),
      });

      if (response.status === 201) {
        const responseData = await response.json();

        const jwtToken = responseData.data.attributes.token;
        if (jwtToken) {
          setToken(jwtToken);
          localStorage.setItem("jwtToken", jwtToken);
          try {
            await invoke("save_auth_token", { token: jwtToken });
          } catch (_e) {}
        }

        const account = decodeTokenManually(jwtToken) as Record<string, unknown>;

        if (!account?.account_id) {
          setIsAccountConfigRequired(true);
          navigate("/account-setup", {
            state: {
              username: username,
              password: password,
            },
          });
        } else {
          setIsAccountConfigRequired(false);
          navigate("/welcome");
        }

        // Resolve display name from /me endpoint
        if (jwtToken) {
          const name = await fetchUserNameFromMe(jwtToken);
          setUserName(name ?? username);
        } else {
          setUserName(username);
        }

        setIsAuthenticated(true);
        setError("");
      } else {
        setError("Authentication failed. Please check your credentials.");
      }
    } catch (_err) {
      setError("An error occurred during authentication.");
    }
  }

  useEffect(() => {
    const initializeApp = async () => {
      const savedToken = localStorage.getItem("jwtToken");
      const currentPath = window.location.pathname;
      try {
        await invoke("set_api_base_url", { base: API_BASE_URL });
      } catch (_e) {}

      if (savedToken) {
        // Best-effort derive a display name from JWT if available
        const decoded = ((): Record<string, unknown> | null => {
          try { return decodeTokenManually(savedToken) as Record<string, unknown>; } catch { return null; }
        })();
        if (decoded) {
          const n = (decoded as any)?.name || (decoded as any)?.email || null;
          if (n) setUserName(String(n));
        }

        setToken(savedToken);
        setIsAuthenticated(true);
        try {
          await invoke("save_auth_token", { token: savedToken });
        } catch (_e) {}
        try {
          const name = await fetchUserNameFromMe(savedToken);
          if (name) setUserName(name);
        } catch {}

        if (currentPath == "/signin") {
          if (isAccountConfigRequired) {
            navigate("/account-setup");
          } else {
            navigate("/welcome");
          }
        }
      } else {
        navigate("/signin");
      }
    };

    initializeApp();
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await listen("auth:invalidated", () => {
          logout();
        });
      } catch (_e) {}
    })();

    return () => {
      if (unlisten) {
        try { unlisten(); } catch (_e) {}
      }
    };
  }, []);

  useEffect(() => {
    (async () => {
      if (!token) return;
      try {
        const name = await fetchUserNameFromMe(token);
        if (name) setUserName(name);
      } catch {}
    })();
  }, [token]);

  const logout = () => {
    setToken(null);
    setIsAuthenticated(false);
    localStorage.removeItem("jwtToken");
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
        token,
        isAuthenticated,
        isAccountConfigRequired,
        error,
        userName,
        checkAuthentication,
        authenticateUser,
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
