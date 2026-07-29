import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  // wasm + topLevelAwait let the (dynamically imported, code-split) Keystone USB
  // SDK load its WebAssembly serialization lib. They only affect that async
  // chunk; the initial bundle is unaffected.
  plugins: [react(), wasm(), topLevelAwait()],
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
    coverage: {
      // v8 is the native, zero-instrumentation provider (matches our vitest 3.x).
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      // Only the app source counts toward coverage; exclude config, type-only
      // declarations, test files, and test helpers so the numbers reflect
      // exercised product code rather than scaffolding.
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/**/*.d.ts",
        "src/test-setup.ts",
        "src/test-utils/**",
        "src/main.tsx",
        "src/vite-env.d.ts",
      ],
      // No hard thresholds yet: this is a baseline-only configuration so CI is
      // never broken by coverage. Raise `thresholds` here once a floor is agreed.
    },
  },
});
