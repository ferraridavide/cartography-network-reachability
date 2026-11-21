import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies /api to a running `cartography-reachability serve`.
const apiTarget = process.env.REACHABILITY_API_URL || "http://127.0.0.1:8000";

export default defineConfig(({ command }) => ({
  plugins: [react()],
  // public/ only holds local bundle JSON for static mode: never copy it into a build.
  publicDir: command === "build" ? false : "public",
  build: {
    // Built into the Python package so `cartography-reachability serve` can ship it.
    outDir: "../cartography_reachability/web",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": apiTarget,
    },
  },
}));
