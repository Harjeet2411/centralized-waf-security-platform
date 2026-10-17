import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(import.meta.dirname, "./src") },
  },
  build: { chunkSizeWarningLimit: 1500 }, // Cloudscape's shared chunk is ~600 kB (170 kB gzip)
  server: {
    port: 5000,
    host: "0.0.0.0",
    // Same-origin in dev too: the HttpOnly session cookie and SameSite=Strict work unchanged.
    proxy: {
      "/api": "http://localhost:8000",
      "/ws": { target: "ws://localhost:8000", ws: true },
    },
  },
});
