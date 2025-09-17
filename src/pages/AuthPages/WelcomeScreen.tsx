import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
// Removed Close button; no window API needed
import Button from "../../components/ui/button/Button";
import klaayLogo from "../../icons/KLAAY-LOGO-RGB_ICON.png";

export const WelcomeScreen: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { accountName, accountId } = location.state || {};
  const [deviceUUID, setDeviceUUID] = useState<string | null>(null);

  useEffect(() => {
    const getDeviceId = async () => {
      try {
      const uuid = "unknown";
        setDeviceUUID(uuid as string);
      } catch (error) {
        console.error("Failed to get device UUID:", error);
      }
    };
    getDeviceId();
  }, []);

  // Close button removed

  // Data collection navigation removed; background collection runs in Rust

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8 bg-[#0B223D]">
      {/* Header with Klaay Logo */}
      <div className="flex items-center justify-center mb-4 text-center">
        <img
          src={klaayLogo}
          alt="Klaay Logo"
          className="w-16 h-16 mr-3"
        />
        <span className="text-white text-2xl font-bold">KlaayGuard</span>
      </div>

      {/* Main Content */}
      <div className="text-center mb-12">
        <h1 className="text-3xl font-bold text-white mb-4">
          Hi {accountName || "User"}, Your KlaayGuard App is installed
        </h1>
        <p className="text-xl text-white">
          Connection status: <span className="text-blue-300">Active</span>
        </p>
      </div>

      {/* Close Button removed */}

      {/* Footer (device ID link removed) */}
      <div className="absolute bottom-8 left-8 right-8 flex justify-between text-white text-sm">
        <div />
        {/* Data collection button removed */}
      </div>
    </div>
  );
};

export default WelcomeScreen;
