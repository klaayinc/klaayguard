import React from "react";
import { useApiEnv } from "../../context/ApiEnvContext";

const ApiEnvToggle: React.FC = () => {
  const { env, toggleEnv, baseUrl } = useApiEnv();
  const isProd = env === "prod";
  return (
    <button
      onClick={toggleEnv}
      title={`Switch API env (current: ${env})`}
      className="inline-flex items-center gap-2 rounded-full border border-gray-200 bg-white px-3 py-1 text-xs text-gray-700 shadow-sm hover:bg-gray-50 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-300 dark:hover:bg-gray-800"
   >
      <span className={`h-2 w-2 rounded-full ${isProd ? "bg-emerald-500" : "bg-amber-500"}`} />
      <span className="font-medium uppercase">{isProd ? "PROD" : "DEV"}</span>
      <span className="hidden sm:inline text-gray-400">{baseUrl.replace(/^https?:\/\//, "")}</span>
    </button>
  );
};

export default ApiEnvToggle;
