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
  }, [navigate]);

  useEffect(() => {
    const handler = (event: MessageEvent) => {
      if (event.source !== iframeRef.current?.contentWindow) return
      const { type, url } = event.data || {}
      if (type === 'OPEN_EXTERNAL' && typeof url === 'string') {
        // Open in default browser via Tauri shell plugin (available in this app)
        import('@tauri-apps/plugin-shell').then(({ open }) => {
          void open(url).catch(() => {})
        })
      }
    }
    window.addEventListener('message', handler)
    return () => window.removeEventListener('message', handler)
  }, [])

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
            sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation"
        // Allow Federated Credential Management (FedCM) for Google Sign-In inside iframe
        allow="identity-credentials-get"
      />
    </div>
  );
}
