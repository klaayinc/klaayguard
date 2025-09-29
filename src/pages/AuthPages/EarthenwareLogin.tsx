import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { invoke } from "@tauri-apps/api/core";
import klaayLogo from "../../icons/KLAAY-LOGO-RGB_ICON.png";

const EARTHENWARE_URL = import.meta.env.VITE_EARTHENWARE_URL as string;
if (!EARTHENWARE_URL) {
  throw new Error("VITE_EARTHENWARE_URL is required");
}

export default function EarthenwareLogin() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    // If user is already authenticated, redirect to welcome screen
    if (isAuthenticated) {
      navigate("/welcome");
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    // Handle device info requests from earthenware iframe
    const handleMessage = async (event: MessageEvent) => {
      if (event.data?.type === 'REQUEST_DEVICE_INFO') {
        try {
          const deviceInfo = await invoke('get_device_info');
          // Send device info back to the iframe
          event.source?.postMessage({
            type: 'DEVICE_INFO_RESPONSE',
            deviceInfo: deviceInfo
          }, '*');
        } catch (error) {
          console.error('Failed to get device info:', error);
          // Send empty response on error
          event.source?.postMessage({
            type: 'DEVICE_INFO_RESPONSE',
            deviceInfo: null
          }, '*');
        }
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  // If authenticated, don't render login
  if (isAuthenticated) {
    return null;
  }

  const loginUrl = `${EARTHENWARE_URL}/login?app=klaayguard`;

  const handleOpen = async (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    try {
      const { open } = await import("@tauri-apps/plugin-shell");
      await open(loginUrl);
    } catch {
      // Fallback: open in default browser
      try { window.open(loginUrl, "_blank"); } catch {}
    }
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-[#0B223D] relative">
      <div className="max-w-md w-full text-center p-8">
        <div className="flex items-center justify-center mb-6">
          <img src={klaayLogo} alt="Klaay Logo" className="w-12 h-12 mr-3" />
          <span className="text-white text-2xl font-bold">KlaayGuard</span>
        </div>
        <h1 className="text-white text-xl font-semibold mb-3">Sign in to Klaay</h1>
        <p className="text-white/80 mb-8">Continue in your browser to authenticate.</p>
        <a
          href={loginUrl}
          onClick={handleOpen}
          className="inline-flex items-center justify-center rounded bg-white text-[#0B223D] px-5 py-3 font-medium hover:bg-gray-100"
        >
          Open Sign-in Page
        </a>
      </div>
    </div>
  );
}
