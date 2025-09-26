import React, { useEffect, useState } from "react";
import { useAuth } from "../../context/AuthContext";
// Removed Close button; no window API needed
import klaayLogo from "../../icons/KLAAY-LOGO-RGB_ICON.png";
import { invoke } from "@tauri-apps/api/core";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";

export const WelcomeScreen: React.FC = () => {
  const { userName } = useAuth();
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const tick = async () => {
      try {
        const secs = await invoke<number>("get_next_run_in_seconds");
        setSecondsLeft(secs);
      } catch {
        // ignore
      }
    };
    // initial + interval
    void tick();
    const timer = window.setInterval(tick, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, []);

  // Close button removed

  // Data collection navigation removed; background collection runs in Rust

  const formatCountdown = (secs: number | null) => {
    if (secs === null) return "--:--";
    if (secs < 0) return "Sign in required";
    const s = Math.max(0, secs);
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m.toString().padStart(2, "0")}:${r.toString().padStart(2, "0")}`;
  };

  useEffect(() => {
    if (secondsLeft !== null && secondsLeft < 0) {
      toast.info("Session expired. Please sign in to continue.");
      navigate("/signin");
    }
  }, [secondsLeft, navigate]);

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8 bg-[#0B223D] relative">
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
          Hi {userName || "User"}, Your KlaayGuard App is installed
        </h1>
        <p className="text-xl text-white">
          Next collection in: <span className="text-blue-300">{formatCountdown(secondsLeft)}</span>
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
