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

  // No longer check first launch or handle osquery installation

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
      } else {
        setIsAuthenticated(false);
      }
    } catch (err) {
      console.error("Error checking authentication:", err);
      setIsAuthenticated(false);
    }
  }

  const decodeTokenManually = (token: string) => {
    try {
      const payload = jwtDecode(token);
      console.log(
        "Decoded Payload:",
        payload.iss,
        payload.sub,
        payload.aud,
        payload.exp,
        payload.nbf,
        payload.iat,
        payload.jti
      );
      return payload;
    } catch (error) {
      console.error("Failed to decode JWT:", error);
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
          } catch (e) {
            console.error("Failed to persist token to Rust state:", e);
          }
        }

        const user = responseData.included?.[0]?.attributes;
        //
        const account = decodeTokenManually(jwtToken) as Record<string, unknown>;

        console.log("Decoded Account:", account);

        if (!account?.account_id) {
          setIsAccountConfigRequired(true);
          console.log("Not Found Account ID, Navigating to Account Setup");
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

        console.log("Authenticated User:", user);
        console.log("Authenticated Account:", account);

        setIsAuthenticated(true);
        setError("");
      } else {
        setError("Authentication failed. Please check your credentials.");
      }
    } catch (err) {
      console.error("Error authenticating user:", err);
      setError("An error occurred during authentication.");
    }
  }

  useEffect(() => {
    const initializeApp = async () => {
      const savedToken = localStorage.getItem("jwtToken");
      const currentPath = window.location.pathname;
      try {
        await invoke("set_api_base_url", { base: API_BASE_URL });
      } catch (e) {
        console.error("Failed to set API base URL in Rust state:", e);
      }

      console.log("Account Config Required:", isAccountConfigRequired);
      if (savedToken) {
        if (isAccountConfigRequired) {
          console.log("savedToken", savedToken);
          setToken(savedToken);
          setIsAuthenticated(true);
          try {
            await invoke("save_auth_token", { token: savedToken });
          } catch (e) {
            console.error("Failed to sync saved token to Rust state:", e);
          }
          if (currentPath == "/signin") {
            navigate("/account-setup");
          }
        } else {
          console.log("savedToken", savedToken);
          setToken(savedToken);
          setIsAuthenticated(true);
          try {
            await invoke("save_auth_token", { token: savedToken });
          } catch (e) {
            console.error("Failed to sync saved token to Rust state:", e);
          }
          if (currentPath == "/signin") {
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
      } catch (e) {
        console.error("Failed to bind auth:invalidated listener:", e);
      }
    })();

    return () => {
      if (unlisten) {
        try { unlisten(); } catch (_e) { /* ignore */ }
      }
    };
  }, []);

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
