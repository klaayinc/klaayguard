import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { MdLogout, MdArrowBack } from "react-icons/md";
import Button from "../../components/ui/button/Button";

export const Home = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { token, logout } = useAuth();
  const { accountName, accountId } = location.state || {};

  useEffect(() => {
    if (!token) return;

    const runCycle = async () => {
      try {
        // 1) GET config
        const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/klaayguard/config`, {
          method: "GET",
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) return;
        const cfg = await response.json();
        const tables: string[] = (cfg?.data || []).map((d: { id: string }) => d.id);
        if (!tables.length) return;

        // 2) osquery via Tauri
        const queryResult = await invoke<Record<string, unknown>>("execute_query", {
          tableNames: tables,
        });

        // 3) device uuid
        const deviceUUID = await invoke<string>("get_device_uuid").catch(() => "unknown");

        // 4) format + POST
        const formatted = Object.entries(queryResult || {}).flatMap(([type, entries]) => {
          if (Array.isArray(entries) && entries.length) {
            return (entries as unknown[]).map((entry) => ({ type, attributes: entry }));
          }
          return [] as { type: string; attributes: unknown }[];
        });

        await fetch(`${import.meta.env.VITE_API_BASE_URL}/klaayguard/data`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
          body: JSON.stringify({ device_uuid: deviceUUID, data: formatted }),
        });
      } catch (_e) {
        // swallow
      }
    };

    // initial + 15-minute interval
    runCycle();
    const id = setInterval(runCycle, 15 * 60 * 1000);
    return () => clearInterval(id);
  }, [token]);

  const handleLogout = () => {
    logout();
    navigate("/signin");
  };

  const handleGoBack = () => {
    navigate("/welcome", {
      state: {
        accountName,
        accountId,
      },
    });
  };

  const handleConfigRowClick = (tableName: string) => {
    setSelectedConfig(tableName);
    // Clear previous query result
    setQueryResult(null);
    // Execute query for the selected table
    execute_query([tableName]);
  };

  return (
    <div className="home items-center relative p-6 bg-gray-100 min-h-screen">
      <div className="flex justify-between mb-4">
        <Button onClick={handleGoBack} variant="outline" title="Go Back">
          <MdArrowBack />
        </Button>
        <Button onClick={handleLogout} variant="outline" title="Logout">
          <MdLogout />
        </Button>
      </div>
      <h1 className="text-2xl font-bold text-center text-gray-800 mb-4">
        Welcome to the KlaayGuard
      </h1>
      <p className="text-center text-gray-600 mb-6">You're signed in. Use the menu to navigate.</p>
    </div>
  );
};
