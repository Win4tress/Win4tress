import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Tauri expects a fixed dev port and serves `dist` in release builds. The
// bundle loads from disk, not a network, so the size warning sits higher than
// Vite's 500 kB (every country flag is in it); the map's shapes load apart.
export default defineConfig({
  plugins: [svelte()],
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "es2022", outDir: "dist", chunkSizeWarningLimit: 800 },
});
