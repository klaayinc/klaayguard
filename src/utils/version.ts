/**
 * Version utility for KlaayGuard
 * Gets version from Tauri backend
 */

import { invoke } from "@tauri-apps/api/core";

let cachedVersion: string | null = null;

export const getAppVersion = async (): Promise<string> => {
  if (cachedVersion) {
    return cachedVersion;
  }

  try {
    // Get version from Tauri backend
    cachedVersion = await invoke<string>("get_app_version");
    return cachedVersion;
  } catch (error) {
    console.warn("Failed to get version from Tauri:", error);
    // Fallback version
    cachedVersion = "0.1.10";
    return cachedVersion;
  }
};

export const getVersionDisplay = async (): Promise<string> => {
  const version = await getAppVersion();
  return `v${version}`;
};
