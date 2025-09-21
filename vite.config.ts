import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// import tailwindcss from "@tailwindcss/vite";
import svgr from "vite-plugin-svgr";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST || "0.0.0.0";

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [
    react(),
    // tailwindcss(),
    svgr({
      svgrOptions: {
        icon: true,
        // This will transform your SVG to a React component
        exportType: "named",
        namedExport: "ReactComponent",
      },
    }),
  ],

  // Define app environment for frontend usage
  define: {
    __KLAAY_ENV__: JSON.stringify(
      process.env.KLAAY_ENV || process.env.NODE_ENV || "production"
    ),
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
