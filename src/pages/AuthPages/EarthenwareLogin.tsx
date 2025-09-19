import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

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
      if (event.origin !== EARTHENWARE_URL) {
        return;
      }

      const { type, data } = event.data;

      if (type === "AUTH_SUCCESS") {
        // Handle successful authentication
        const { token: authToken, needsAccountSelection } = data;
        
        // Store the token in localStorage (this will be picked up by AuthContext)
        localStorage.setItem("jwtToken", authToken);
        
        // If account selection is needed, we might need to handle that
        // For now, just proceed with authentication
        if (needsAccountSelection) {
          console.log("Account selection needed, but proceeding with authentication");
        }
        
        // Trigger authentication check in the context
        window.location.reload();
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
        allow="camera; microphone; geolocation"
        sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox"
      />
    </div>
  );
}
