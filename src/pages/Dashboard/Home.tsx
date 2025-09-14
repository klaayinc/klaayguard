import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { invoke } from "@tauri-apps/api/core";
import { useAuth } from "../../context/AuthContext";
import { MdLogout, MdArrowBack } from "react-icons/md";
import { API_BASE_URL } from "../../constants/api";
import Button from "../../components/ui/button/Button";
import { Spinner } from "../../components/ui/spinner/Spinner";
import CopyableText from "../../components/ui/CopyableText";

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
  const [monitoringStatus, setMonitoringStatus] = useState<string>("Initializing...");
  const [lastSyncTime, setLastSyncTime] = useState<string>("Never");
  const [lastOsqueryTime, setLastOsqueryTime] = useState<string>("Never");
  const [nextOsqueryTime, setNextOsqueryTime] = useState<string>("Calculating...");
  const [syncStatus, setSyncStatus] = useState<string>("Unknown");
  const [collectionStatus, setCollectionStatus] = useState<string>("Unknown");
  const [lastUpdate, setLastUpdate] = useState<string>("Never");

  useEffect(() => {
    const getDeviceId = async () => {
      const uuid = await get_device_uuid();
      setDeviceUUID(uuid);
    };
    getDeviceId();
  }, []);

  useEffect(() => {
    // Initialize backend monitoring service
    const initializeMonitoring = async () => {
      try {
        // Set auth token for the monitoring service
        await invoke('set_auth_token', { token });
        
        // Start the monitoring service
        await invoke('start_monitoring');
        setMonitoringStatus("Monitoring service started");
        
        // Fetch initial configuration for display
        await fetchConfiguration();
        
        // Load initial data for display
        await loadInitialData();
        
        // Load sync information
        await loadSyncInfo();
      } catch (error) {
        console.error('Failed to initialize monitoring service:', error);
      }
    };
    
    initializeMonitoring();
    
    // Cleanup on unmount
    return () => {
      invoke('stop_monitoring').catch(console.error);
    };
  }, [token]);

  // Remove this useEffect since data posting is now handled by the backend monitoring service
  // useEffect(() => {
  //   if (queryResult) {
  //     postDataToApi();
  //   }
  // }, [queryResult]);

  // Load initial data for display purposes
  async function loadInitialData() {
    try {
      if (config && config.data.length > 0 && !selectedConfig) {
        const defaultConfig =
          config.data.find((item) => item.id === "system_info") || config.data[0];
        setSelectedConfig(defaultConfig.id);
        await execute_query([defaultConfig.id]);
      }
    } catch (error) {
      console.error('Failed to load initial data:', error);
    }
  }

  // Load sync information from backend
  async function loadSyncInfo() {
    try {
      const syncInfo = await invoke<{
        last_sync_time: string;
        last_attempt_time: string;
        consecutive_failures: number;
        last_osquery_time: string;
        next_osquery_time: string;
        monitoring_active: boolean;
        device_uuid: string;
      }>('get_sync_info');
      
      setLastSyncTime(syncInfo.last_sync_time === "Never" ? "Never" : new Date(syncInfo.last_sync_time).toLocaleString());
      setLastOsqueryTime(new Date(syncInfo.last_osquery_time).toLocaleString());
      setNextOsqueryTime(new Date(syncInfo.next_osquery_time).toLocaleString());
      setSyncStatus(syncInfo.consecutive_failures > 0 ? `Failed (${syncInfo.consecutive_failures} attempts)` : "Success");
      
      console.log('Sync info loaded:', syncInfo);
    } catch (error) {
      console.error('Failed to load sync info:', error);
      setSyncStatus("Error loading sync info");
    }
  }

  // Load collection status from backend
  async function loadCollectionStatus() {
    try {
      const collectionInfo = await invoke<{
        is_running: boolean;
        device_uuid: string;
        last_collection: string;
        next_collection: string;
        collection_interval_minutes: number;
        status: string;
      }>('get_collection_status');
      
      setCollectionStatus(collectionInfo.status);
      setLastOsqueryTime(new Date(collectionInfo.last_collection).toLocaleString());
      setNextOsqueryTime(new Date(collectionInfo.next_collection).toLocaleString());
      
      console.log('Collection status loaded:', collectionInfo);
    } catch (error) {
      console.error('Failed to load collection status:', error);
      setCollectionStatus("Error loading status");
    }
  }

  useEffect(() => {
    // Load data when config changes
    if (config && config.data.length > 0 && !selectedConfig) {
      loadInitialData();
    }
  }, [config, selectedConfig]);

  // Automatically sync with backend status
  useEffect(() => {
    const syncWithBackend = async () => {
      try {
        // Check monitoring status
        const status = await invoke<string>("get_monitoring_status");
        setMonitoringStatus(status);
        
        // Load sync information
        await loadSyncInfo();
        
        // Load collection status
        await loadCollectionStatus();
        
        // Load fresh data if monitoring is active
        if (status.includes("running")) {
          await loadInitialData();
        }
        
        // Update last sync time
        setLastUpdate(new Date().toLocaleTimeString());
      } catch (error) {
        console.error('Failed to sync with backend:', error);
        setMonitoringStatus(`Sync error: ${error}`);
      }
    };

    // Initial sync
    syncWithBackend();

    // Set up automatic sync every 10 seconds
    const interval = setInterval(syncWithBackend, 10000);

    return () => clearInterval(interval);
  }, []);

  async function fetchConfiguration() {
    try {
      console.log("Fetching configuration from API...");
      const response = await fetch(`${API_BASE_URL}/klaayguard/config`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = (await response.json()) as Config;
        console.log("Configuration received:", data);
        setConfig(data);
        const tableNames = data.data.map((item) => item.id);
        console.log("Request Query for these tables: ", tableNames);
        // Don't execute query here - let loadInitialData handle it
      } else {
        console.error("Failed to fetch configuration. Status:", response.status);
        setError(`Failed to fetch configuration: ${response.status}`);
      }
    } catch (err) {
      console.error("Error fetching configuration:", err);
      setError(`Error fetching configuration: ${err}`);
    }
  }

  // Data posting is now handled by the backend monitoring service
  // This function is kept for manual testing if needed
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
      console.log("Executing query for tables:", tableNames);
      setIsLoading(true);
      setQueryResult(null); // Clear previous results immediately
      const response = await invoke<DeepRecord | null>("execute_query", {
        tableNames,
      });
      console.log("Query response:", response);
      if (!response) {
        setError("No data received from the query.");
        return;
      }
      setQueryResult(response);
      setError("");
      console.log("Query result set successfully");
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
        <div className="mb-6 mx-auto flex justify-center items-center max-w-lg border border-gray-300 rounded-md p-2 bg-white">
          <CopyableText
            text={deviceUUID}
            label="Device ID"
            className="text-center"
          />
        </div>
      )}
      
      {/* Debug Information */}
      <div className="mb-6 mx-auto max-w-4xl border border-blue-300 rounded-md p-4 bg-blue-50">
        <h3 className="text-lg font-semibold text-blue-800 mb-4">Monitoring & Sync Status</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Basic Status */}
          <div className="space-y-2 text-sm">
            <h4 className="font-semibold text-blue-700">Basic Status</h4>
            <div><strong>Monitoring Status:</strong> {monitoringStatus}</div>
            <div><strong>Config Loaded:</strong> {config ? "Yes" : "No"}</div>
            <div><strong>Data Available:</strong> {queryResult ? "Yes" : "No"}</div>
            <div><strong>Selected Config:</strong> {selectedConfig || "None"}</div>
            <div><strong>Loading:</strong> {isLoading ? "Yes" : "No"}</div>
          </div>
          
          {/* Sync Timing */}
          <div className="space-y-2 text-sm">
            <h4 className="font-semibold text-blue-700">Sync & Timing</h4>
            <div><strong>Collection Status:</strong> 
              <span className={`ml-1 px-2 py-1 rounded text-xs ${
                collectionStatus === "active" ? "bg-green-100 text-green-800" : 
                collectionStatus === "inactive" ? "bg-red-100 text-red-800" : 
                "bg-yellow-100 text-yellow-800"
              }`}>
                {collectionStatus}
              </span>
            </div>
            <div><strong>Last API Sync:</strong> {lastSyncTime}</div>
            <div><strong>Last Osquery:</strong> {lastOsqueryTime}</div>
            <div><strong>Next Osquery:</strong> {nextOsqueryTime}</div>
            <div><strong>Sync Status:</strong> 
              <span className={`ml-1 px-2 py-1 rounded text-xs ${
                syncStatus === "Success" ? "bg-green-100 text-green-800" : 
                syncStatus.includes("Failed") ? "bg-red-100 text-red-800" : 
                "bg-yellow-100 text-yellow-800"
              }`}>
                {syncStatus}
              </span>
            </div>
            <div><strong>Last Update:</strong> {lastUpdate}</div>
          </div>
        </div>
        <div className="mt-4 text-sm text-gray-600">
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${
              monitoringStatus.includes("running") ? "bg-green-500" : 
              monitoringStatus.includes("stopped") ? "bg-red-500" : 
              monitoringStatus.includes("error") ? "bg-red-500" : 
              "bg-yellow-500"
            }`}></div>
            <span>Auto-syncing every 10 seconds</span>
          </div>
        </div>
      </div>
      
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
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="sticky top-0 z-10 bg-gray-50">
                <tr>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    Type
                  </th>
                  <th
                    scope="col"
                    className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                  >
                    ID
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {config?.data?.map((item, index: number) => (
                  <tr
                    key={index}
                    className="hover:bg-gray-50 transition-colors cursor-pointer"
                    onClick={() => handleConfigRowClick(item.id)}
                  >
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {item.type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {item.id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
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
