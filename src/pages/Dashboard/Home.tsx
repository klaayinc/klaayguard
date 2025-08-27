import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useAuth } from "../../context/AuthContext";
import { MdLogout, MdArrowBack } from "react-icons/md";
import { API_BASE_URL } from "../../constants/api";
import Button from "../../components/ui/button/Button";
import { Spinner } from "../../components/ui/spinner/Spinner";

export const Home = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { token, logout } = useAuth();
  const { accountName, accountId } = location.state || {};

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
  const [deviceUUID, setDeviceUUID] = useState<string | null>(null);
  const [queryResult, setQueryResult] = useState<DeepRecord | null>(null);
  const [error, setError] = useState("");
  const [selectedConfig, setSelectedConfig] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    const getDeviceId = async () => {
      const uuid = await get_device_uuid();
      setDeviceUUID(uuid);
    };
    getDeviceId();
  }, []);

  useEffect(() => {
    // Start fetching configuration immediately and then on an interval
    fetchConfiguration();
    const interval = setInterval(() => {
      fetchConfiguration();
    }, 15 * 60 * 1000); // 15 minutes
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (queryResult) {
      postDataToApi();
    }
  }, [queryResult]);

  useEffect(() => {
    // Set default configuration and load data when config is available
    if (config && config.data.length > 0 && !selectedConfig) {
      const defaultConfig =
        config.data.find((item) => item.id === "system_info") || config.data[0];
      setSelectedConfig(defaultConfig.id);
      execute_query([defaultConfig.id]);
    }
  }, [config, selectedConfig]);

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
      if (!deviceUUID) {
        console.error("No device uuid.");
        return;
      }
      if (!queryResult) {
        console.error("No data to post.");
        return;
      }
      const formattedData = Object.entries(queryResult || {}).flatMap(
        ([type, entries]) => {
          if (Array.isArray(entries) && entries.length !== 0) {
            return entries.map((entry: DeepRecord) => ({
              type,
              attributes: entry,
            }));
          }
          return [];
        }
      );

      const response = await fetch(`${API_BASE_URL}/klaayguard/data`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ device_uuid: deviceUUID, data: formattedData }),
      });

      if (!response.ok) {
        console.error("Failed to post data to API.");
      }
    } catch (err) {
      console.error("Error posting data to API:", err);
    }
  }

  async function get_device_uuid(): Promise<string | null> {
    try {
      const response = await invoke<string>("get_device_uuid");
      return response;
    } catch (error) {
      console.error("Error getting device id: ", error);
      return null;
    }
  }

  async function execute_query(tableNames: string[]) {
    try {
      setIsLoading(true);
      setQueryResult(null); // Clear previous results immediately
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
      setError("Error executing query");
    } finally {
      setIsLoading(false);
    }
  }

  const renderCellValue = (value: DeepRecord) => {
    if (typeof value === "object" && value !== null) {
      return (
        <pre className="text-xs max-w-[300px] overflow-x-auto">
          {JSON.stringify(value, null, 2)}
        </pre>
      );
    }
    if (typeof value === "string") {
      return value.length > 100 ? `${value.slice(0, 100)}...` : value;
    }
    return String(value);
  };

  const getCellTitle = (value: DeepRecord): string | undefined =>
    typeof value === "string" ? value : undefined;

  const renderQueryResult = () => {
    if (!queryResult || typeof queryResult !== "object") {
      return (
        <pre className="whitespace-pre-wrap">
          {JSON.stringify(queryResult, null, 2)}
        </pre>
      );
    }

    return Object.entries(queryResult).map(([tableName, tableData]) => (
      <div key={tableName} className="mb-8">
        <h3 className="text-lg font-medium text-gray-800 mb-3 capitalize">
          {tableName.replace(/_/g, " ")}
        </h3>
        {Array.isArray(tableData) && tableData.length > 0 && (
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
                  <tr
                    key={rowIndex}
                    className="hover:bg-gray-50 transition-colors"
                  >
                    {row &&
                      Object.values(row).map((value, colIndex) => (
                        <td
                          key={colIndex}
                          className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 max-w-[300px] truncate hover:bg-gray-100 transition-colors"
                          title={getCellTitle(value)}
                        >
                          {renderCellValue(value)}
                        </td>
                      ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {(!Array.isArray(tableData) || tableData.length === 0) && (
          <p className="text-gray-500 italic">No data available</p>
        )}
      </div>
    ));
  };

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
      {deviceUUID && (
        <div className="bg-gray-50 border border-gray-200 rounded px-4 py-2 mb-4 mx-auto max-w-lg">
          <p className="text-sm text-gray-700 text-center">
            Device ID:{" "}
            <span className="font-mono bg-gray-100 px-2 py-1 rounded">
              {deviceUUID}
            </span>
          </p>
        </div>
      )}
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <>
        <div className="overflow-x-auto bg-white shadow-md rounded-lg p-4 mb-6">
          <div className="flex justify-between items-center mb-2">
            <h2 className="text-xl font-semibold text-gray-700">
              Configuration (Click to view data)
            </h2>
            {selectedConfig && (
              <Button
                onClick={() => {
                  setSelectedConfig(null);
                  setQueryResult(null);
                  // Execute query for all tables
                  if (config) {
                    const tableNames = config.data.map((item) => item.id);
                    execute_query(tableNames);
                  }
                }}
                variant="outline"
                size="sm"
              >
                Show All
              </Button>
            )}
          </div>
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
                  } hover:bg-blue-50 transition-colors cursor-pointer`}
                  onClick={() => handleConfigRowClick(item.id)}
                >
                  <td className="border px-4 py-2">{item.type}</td>
                  <td className="border px-4 py-2">{item.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {selectedConfig && (
          <div className="overflow-x-auto bg-white shadow-md rounded-lg p-4 mb-6">
            <h2 className="text-xl font-semibold text-gray-700 mb-2">
              Query Result for: {selectedConfig}
            </h2>
            {isLoading ? <Spinner /> : queryResult ? renderQueryResult() : null}
          </div>
        )}
      </>
    </div>
  );
};
