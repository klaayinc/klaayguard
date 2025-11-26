#!/usr/bin/env node
const { spawnSync, execSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

// KLAAY_ENV determines which environment to build for. Defaults to production.
// Allowed values: production | staging | development
const KLAAY_ENV_RAW = (
  process.env.KLAAY_ENV ||
  process.env.NODE_ENV ||
  "production"
).toLowerCase();
const ALLOWED_ENVS = ["production", "staging", "development"];
const KLAAY_ENV = ALLOWED_ENVS.includes(KLAAY_ENV_RAW)
  ? KLAAY_ENV_RAW
  : "production";
if (KLAAY_ENV !== KLAAY_ENV_RAW) {
  console.warn(
    `[tauri-build] Warning: Invalid KLAAY_ENV "${KLAAY_ENV_RAW}", defaulting to "production"`
  );
}

// Load environment variables from .env files using bash script
// This ensures consistency with bin/build and bin/dev
const projectRoot = path.join(__dirname, "..");
const loadEnvScript = path.join(projectRoot, "scripts", "load-env.sh");

if (fs.existsSync(loadEnvScript)) {
  try {
    // Source the script and export variables
    // Use array arguments to prevent command injection
    const envOutput = execSync(
      "bash",
      ["-c", 'source "$1" "$2" && env', "--", loadEnvScript, KLAAY_ENV],
      {
        cwd: projectRoot,
        encoding: "utf8",
      }
    );

    // Parse the output and set environment variables
    envOutput.split("\n").forEach((line) => {
      const match = line.match(/^([^=]+)=(.*)$/);
      if (match && !process.env[match[1]]) {
        process.env[match[1]] = match[2];
      }
    });
  } catch (error) {
    console.error(
      "[tauri-build] Warning: Failed to load environment from .env files:",
      error.message
    );
    console.error(
      "[tauri-build] Continuing with existing environment variables..."
    );
  }
}

// Validate required variables
const requiredVars = ["VITE_API_BASE_URL", "VITE_EARTHENWARE_URL"];
const missingVars = requiredVars.filter((v) => !process.env[v]);

if (missingVars.length > 0) {
  console.error(
    "[tauri-build] Error: Required environment variables are not set:"
  );
  missingVars.forEach((v) => console.error(`  - ${v}`));
  console.error("\nPlease run: scripts/setup-env.sh to create .env files");
  process.exit(1);
}

const hasKey = !!process.env.TAURI_SIGNING_PRIVATE_KEY;
const args = ["build"];
const passThrough = process.argv.slice(2);

// Select a per-env tauri config for environment-specific settings
if (KLAAY_ENV === "staging") {
  args.push("--config", "src-tauri/tauri.staging.json");
} else if (KLAAY_ENV === "development") {
  args.push("--config", "src-tauri/tauri.development.json");
}

if (!hasKey) {
  // Merge override to disable updater artifacts locally
  args.push("--config", "src-tauri/tauri.no-updater.json");
}

// Pass through any additional CLI flags (e.g., --target)
args.push(...passThrough);

function resolveTauriCommand() {
  // Check if cargo-tauri is installed
  try {
    execSync("cargo tauri --version", { stdio: "pipe" });
    return "cargo tauri";
  } catch (error) {
    console.error("[tauri-build] Error: cargo-tauri not found");
    console.error("[tauri-build] Please install: cargo install tauri-cli");
    process.exit(1);
  }
}

const tauriCmd = resolveTauriCommand();
console.log(`[tauri-build] Resolved Tauri command: ${tauriCmd}`);
console.log(`[tauri-build] Command exists: ${fs.existsSync(tauriCmd)}`);
console.log(`[tauri-build] Platform: ${process.platform}`);
console.log(`[tauri-build] Args: ${args.join(" ")}`);

const result = spawnSync(tauriCmd, args, {
  stdio: "inherit",
  env: process.env,
  shell: process.platform === "win32", // Use shell on Windows
});

if (result.error) {
  console.error(
    `[tauri-build] Failed to spawn Tauri CLI: ${result.error.message}`
  );
  process.exit(1);
}

if (typeof result.status !== "number" || result.status !== 0) {
  console.error(
    `[tauri-build] Tauri exited with code ${result.status ?? "unknown"}`
  );
  process.exit(result.status ?? 1);
}

process.exit(0);
