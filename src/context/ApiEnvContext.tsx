import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import { API_ENDPOINTS, ApiEnv, DEFAULT_API_BASE_URL } from "../constants/api";

type ApiEnvContextType = {
  env: ApiEnv; // 'prod' | 'dev'
  baseUrl: string; // current base URL
  setEnv: (env: ApiEnv) => void;
  toggleEnv: () => void;
};

const ApiEnvContext = createContext<ApiEnvContextType | undefined>(undefined);

const STORAGE_KEY = "api.env";

export const ApiEnvProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [env, setEnvState] = useState<ApiEnv>("prod");
  const [initialized, setInitialized] = useState(false);

  useEffect(() => {
    // initialize from localStorage
    const saved = localStorage.getItem(STORAGE_KEY) as ApiEnv | null;
    if (saved === "prod" || saved === "dev") {
      setEnvState(saved);
    } else {
      setEnvState("prod");
    }
    setInitialized(true);
  }, []);

  useEffect(() => {
    if (!initialized) return;
    localStorage.setItem(STORAGE_KEY, env);
  }, [env, initialized]);

  const setEnv = (next: ApiEnv) => setEnvState(next);
  const toggleEnv = () => setEnvState((prev) => (prev === "prod" ? "dev" : "prod"));

  const baseUrl = useMemo(() => {
    // allow override via VITE_API_BASE_URL if provided, but keep toggle-able by suffix matching
    const fromEnv = (import.meta as any).env?.VITE_API_BASE_URL as string | undefined;
    if (fromEnv) {
      // If an explicit env base is set, prefer it but still let toggle swap between known endpoints
      if (env === "prod") return API_ENDPOINTS.prod;
      if (env === "dev") return API_ENDPOINTS.dev;
      return fromEnv ?? DEFAULT_API_BASE_URL;
    }
    return env === "prod" ? API_ENDPOINTS.prod : API_ENDPOINTS.dev;
  }, [env]);

  const value = useMemo(() => ({ env, baseUrl, setEnv, toggleEnv }), [env, baseUrl]);

  return <ApiEnvContext.Provider value={value}>{children}</ApiEnvContext.Provider>;
};

export const useApiEnv = () => {
  const ctx = useContext(ApiEnvContext);
  if (!ctx) throw new Error("useApiEnv must be used within ApiEnvProvider");
  return ctx;
};
