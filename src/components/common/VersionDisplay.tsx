import React, { useState, useEffect } from "react";
import { getVersionDisplay } from "../../utils/version";

interface VersionDisplayProps {
  className?: string;
  position?: "bottom-left" | "bottom-right" | "top-left" | "top-right" | "bottom-center";
}

const VersionDisplay: React.FC<VersionDisplayProps> = ({ 
  className = "", 
  position = "bottom-right" 
}) => {
  const [version, setVersion] = useState<string>("v0.1.10");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const loadVersion = async () => {
      try {
        const versionText = await getVersionDisplay();
        setVersion(versionText);
      } catch (error) {
        console.warn("Failed to load version:", error);
        setVersion("v0.1.10");
      } finally {
        setIsLoading(false);
      }
    };

    loadVersion();
  }, []);
  
  const getPositionClasses = () => {
    switch (position) {
      case "bottom-left":
        return "absolute bottom-4 left-4";
      case "bottom-right":
        return "absolute bottom-4 right-4";
      case "top-left":
        return "absolute top-4 left-4";
      case "top-right":
        return "absolute top-4 right-4";
      case "bottom-center":
        return "absolute bottom-4 left-1/2 transform -translate-x-1/2";
      default:
        return "absolute bottom-4 right-4";
    }
  };

  if (isLoading) {
    return null; // Don't show anything while loading
  }

  return (
    <div className={`${getPositionClasses()} ${className}`}>
      <span className="text-xs text-gray-400 dark:text-gray-500 font-mono">
        {version}
      </span>
    </div>
  );
};

export default VersionDisplay;
