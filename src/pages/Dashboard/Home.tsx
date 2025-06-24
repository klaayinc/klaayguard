import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useAuth } from "../../context/AuthContext";
import { MdLogout } from "react-icons/md";
import { API_BASE_URL } from "../../constants/api";

export const Home = () => {
  const navigate = useNavigate();
  const { token, logout } = useAuth();
  const [osqueryInstalled, setOsqueryInstalled] = useState<boolean | null>(
    null
  );

  const [isOsQueryInstalling, setIsOsQueryInstalling] = useState(false);
  interface ConfigData {
    type: string;
    id: string;
  }

  interface Config {
    data: ConfigData[];
  }

  type DeepRecord =
    | string
    | number
    | boolean
    | null
    | undefined
    | DeepRecord[]
    | { [key: string]: DeepRecord };

  const [config, setConfig] = useState<Config | null>(null);
  const [queryResult, setQueryResult] = useState<DeepRecord | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    checkInstallation();
  }, []);

  useEffect(() => {
    if (!osqueryInstalled) return;
    const interval = setInterval(() => {
      fetchConfiguration();
    }, 15 * 60 * 1000); // 15 minutes
    return () => clearInterval(interval);
  }, [osqueryInstalled]);

  useEffect(() => {
    if (osqueryInstalled) {
      fetchConfiguration();
    }
  }, [osqueryInstalled]);

  useEffect(() => {
    if (queryResult) {
      postDataToApi();
    }
  }, [queryResult]);

  const checkInstallation = async () => {
    try {
      const installed = await invoke<boolean>("check_osquery");
      setOsqueryInstalled(installed);
      setIsOsQueryInstalling(false);
    } catch (err) {
      setError(`Error checking installation: ${err}`);
    }
  };

  const handleInstall = async () => {
    try {
      setIsOsQueryInstalling(true);
      await invoke("install_osquery");
      await checkInstallation();
    } catch (err) {
      setError(`Installation failed: ${err}`);
    }
  };

  async function fetchConfiguration() {
    try {
      const response = await fetch(`${API_BASE_URL}/klaayguard/config`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = (await response.json()) as Config;
        setConfig(data);
        const tableNames = data.data.map((item) => item.id);
        console.log("Request Query for these tables: ", tableNames);
        await execute_query(tableNames);
      } else {
        console.error("Failed to fetch configuration.");
      }
    } catch (err) {
      console.error("Error fetching configuration:", err);
    }
  }

  // Step 4: Post data to API
  async function postDataToApi() {
    try {
      console.log("Posting data to API...", { queryResult });
      if (!queryResult) {
        console.error("No data to post.");
        return;
      }
      const formattedData = Object.entries(queryResult || {}).flatMap(
        ([type, entries]) =>
          Array.isArray(entries) && entries.length !== 0
            ? entries.map((entry: DeepRecord) => ({
                type,
                attributes: entry,
              }))
            : []
      );

      console.log("Formatted data to post:", formattedData);
      const response = await fetch(`${API_BASE_URL}/klaayguard/data`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ data: formattedData }),
      });

      if (!response.ok) {
        console.error("Failed to post data to API.");
      }
    } catch (err) {
      console.error("Error posting data to API:", err);
    }
  }

  async function execute_query(tableNames: string[]) {
    try {
      const response = await invoke<DeepRecord | null>("execute_query", {
        tableNames,
      });
      if (!response) {
        setError("No data received from the query.");
        return;
      }
      setQueryResult(response);
    } catch (error) {
      console.error("Error executing query:", error);
    }
  }

  const handleLogout = () => {
    logout();
    navigate("/signin");
  };

  return (
    <div className="home items-center relative p-6 bg-gray-100 min-h-screen">
      {/* Logout Button */}
      <button
        onClick={handleLogout}
        className="absolute top-4 right-4 text-gray-600 hover:text-red-600"
        title="Logout"
      >
        <MdLogout />
      </button>

      <h1 className="text-2xl font-bold text-center text-gray-800 mb-4">
        Welcome to the Klaay Guard
      </h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      {isOsQueryInstalling ? (
        <p className="text-yellow-600 mb-4">Installing osquery...</p>
      ) : osqueryInstalled === null ? (
        <p>Checking osquery installation...</p>
      ) : osqueryInstalled ? (
        <>
          <div className="overflow-x-auto bg-white shadow-md rounded-lg p-4 mb-6">
            <h2 className="text-xl font-semibold text-gray-700 mb-2">
              Configuration
            </h2>
            <table className="table-auto w-full bg-white shadow-md rounded-lg mb-6">
              <thead className="sticky top-0 z-10 bg-gray-200">
                <tr className="text-gray-700">
                  <th className="px-4 py-2">Type</th>
                  <th className="px-4 py-2">ID</th>
                </tr>
              </thead>
              <tbody>
                {config?.data?.map((item, index: number) => (
                  <tr
                    key={index}
                    className={`${
                      index % 2 === 0 ? "bg-gray-100" : "bg-white"
                    }`}
                  >
                    <td className="border px-4 py-2">{item.type}</td>
                    <td className="border px-4 py-2">{item.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="overflow-x-auto bg-white shadow-md rounded-lg p-4 mb-6">
            <h2 className="text-xl font-semibold text-gray-700 mb-2">
              Query Result
            </h2>
            {queryResult && typeof queryResult === "object" ? (
              Object.entries(queryResult).map(([tableName, tableData]) => (
                <div key={tableName} className="mb-8">
                  <h3 className="text-lg font-medium text-gray-800 mb-3 capitalize">
                    {tableName.replace(/_/g, " ")}
                  </h3>
                  {Array.isArray(tableData) && tableData.length > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="min-w-full divide-y divide-gray-200">
                        <thead className="sticky top-0 z-10 bg-gray-50">
                          <tr>
                            {tableData[0] &&
                              Object.keys(tableData[0]).map((key) => (
                                <th
                                  key={key}
                                  scope="col"
                                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                                >
                                  {key}
                                </th>
                              ))}
                          </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                          {tableData.map((row, rowIndex) => (
                            <tr key={rowIndex}>
                              {row &&
                                Object.values(row).map((value, colIndex) => (
                                  <td
                                    key={colIndex}
                                    className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 max-w-[300px] truncate"
                                    title={
                                      typeof value === "string"
                                        ? value
                                        : undefined
                                    }
                                  >
                                    {typeof value === "object" ? (
                                      <pre className="text-xs max-w-[300px] overflow-x-auto">
                                        {JSON.stringify(value, null, 2)}
                                      </pre>
                                    ) : typeof value === "string" &&
                                      value.length > 100 ? (
                                      <>{value.slice(0, 100)}...</>
                                    ) : (
                                      String(value)
                                    )}
                                  </td>
                                ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p className="text-gray-500 italic">No data available</p>
                  )}
                </div>
              ))
            ) : (
              <pre className="whitespace-pre-wrap">
                {JSON.stringify(queryResult, null, 2)}
              </pre>
            )}
          </div>
        </>
      ) : (
        <div className="flex justify-center items-center min-h-[200px]">
          <button
            onClick={handleInstall}
            className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700"
          >
            Install Osquery
          </button>
        </div>
      )}
    </div>
  );
};
