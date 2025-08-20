import React from "react";
import { useApiEnv } from "../../context/ApiEnvContext";

const DevModeBanner: React.FC = () => {
  const { env, baseUrl } = useApiEnv();
  if (env !== "dev") return null;

  return (
    <div className="fixed inset-x-0 top-0 z-[100000]">
      <div className="pointer-events-none mx-auto w-full">
        <div className="pointer-events-auto flex items-center justify-center gap-3 bg-amber-500 px-3 py-1.5 text-xs font-medium text-white shadow">
          <span>DEV MODE</span>
          <span className="opacity-90">•</span>
          <span>API: {baseUrl.replace(/^https?:\/\//, "")}</span>
        </div>
      </div>
    </div>
  );
};

export default DevModeBanner;
