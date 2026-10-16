/// <reference types="vitest" />
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "#": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:8001",
        changeOrigin: true,
      },
      "/health": {
        target: "http://localhost:8001",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:8001",
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    // No source maps in the production build (#731): nginx served the .map
    // files, which hand anyone who can load the app its original source.
    sourcemap: false,
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
