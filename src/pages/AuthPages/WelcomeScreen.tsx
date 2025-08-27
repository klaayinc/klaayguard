import React, { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { invoke } from "@tauri-apps/api/core";
import CopyableText from "../../components/ui/CopyableText";
import Button from "../../components/ui/button/Button";

export const WelcomeScreen: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { accountName, accountId } = location.state || {};
  const [deviceUUID, setDeviceUUID] = useState<string | null>(null);

  useEffect(() => {
    const getDeviceId = async () => {
      try {
        const uuid = await invoke("get_device_uuid");
        setDeviceUUID(uuid as string);
      } catch (error) {
        console.error("Failed to get device UUID:", error);
      }
    };
    getDeviceId();
  }, []);

  const handleClose = async () => {
    try {
      const appWindow = getCurrentWindow();
      await appWindow.hide();
    } catch (error) {
      console.error("Failed to hide window:", error);
      alert("Something went wrong while trying to hide the window");
    }
  };

  const handleDataCollection = () => {
    navigate("/home", {
      state: {
        accountName,
        accountId,
      },
    });
  };

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center p-8"
      style={{ backgroundColor: "#0B223D" }}
    >
      {/* Header with Klaay Logo */}
      <div className="text-center mb-12">
        <div className="flex items-center justify-center mb-4">
          <img
            src="/src/icons/KLAAY-LOGO-RGB_ICON.png"
            alt="Klaay Logo"
            className="w-16 h-16 mr-3"
          />
          <span className="text-white text-2xl font-bold">Klaay</span>
        </div>
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

      {/* Close Button */}
      <Button onClick={handleClose}>Close this window</Button>

      {/* Footer */}
      <div className="absolute bottom-8 left-8 right-8 flex justify-between text-white text-sm">
        <CopyableText
          text={deviceUUID || "Loading..."}
          label="Device ID"
          className="text-white"
        />
        <Button
          variant="outline"
          onClick={handleDataCollection}
          className="bg-inherit border-none text-white hover:text-black"
        >
          Data collection
        </Button>
      </div>
    </div>
  );
};

export default WelcomeScreen;
