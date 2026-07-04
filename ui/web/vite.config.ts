import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { outDir: "../internal/webui/dist", emptyOutDir: true },
  server: {
    proxy: {
      "/status": "http://127.0.0.1:8090",
      "/health": "http://127.0.0.1:8090",
      "/vault": "http://127.0.0.1:8090",
      "/wallet": "http://127.0.0.1:8090",
      "/connector": "http://127.0.0.1:8090",
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test-setup.ts",
  },
});
