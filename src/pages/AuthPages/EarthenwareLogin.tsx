import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { invoke } from "@tauri-apps/api/core";

const EARTHENWARE_URL = import.meta.env.VITE_EARTHENWARE_URL as string;
if (!EARTHENWARE_URL) {
  throw new Error("VITE_EARTHENWARE_URL is required");
}

export default function EarthenwareLogin() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    // If user is already authenticated, redirect to welcome screen
    if (isAuthenticated) {
      navigate("/welcome");
    }
  }, [isAuthenticated, navigate]);

  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      // Only accept messages from Earthenware origin
      const expectedOrigin = new URL(EARTHENWARE_URL).origin;
      if (event.origin !== expectedOrigin) {
        return;
      }

      const { type, data } = event.data;

      if (type === "AUTH_SUCCESS") {
        // Handle successful authentication
        const { token: authToken } = data;

        // Persist token in Tauri backend (Keychain) and navigate
        void invoke("save_auth_token", { token: authToken })
          .then(() => {
            navigate("/welcome");
          })
          .catch(() => {
            // If saving fails, stay on signin
          });
      } else if (type === "AUTH_ERROR") {
        // Handle authentication error
        console.error("Authentication error:", data.error);
      }
    };

    window.addEventListener("message", handleMessage);
    return () => window.removeEventListener("message", handleMessage);
  }, []);

  // If authenticated, don't render the iframe
  if (isAuthenticated) {
    return null;
  }

  return (
    <div className="h-screen w-screen">
      <iframe
        ref={iframeRef}
        src={`${EARTHENWARE_URL}/login`}
        className="h-full w-full border-0"
        title="Earthenware Login"
        // Minimize permissions; expand only if strictly required by Earthenware login
        sandbox="allow-same-origin allow-scripts allow-forms"
      />
    </div>
  );
}
