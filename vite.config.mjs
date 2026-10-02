import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { defineConfig } from "vite";

const projectRoot = fileURLToPath(new URL(".", import.meta.url));
const clientRoot = resolve(projectRoot, "client");

export default defineConfig(({ command }) => ({
  root: clientRoot,
  base: command === "build" ? "./" : "/",
  publicDir: resolve(projectRoot, "public"),
  server: {
    proxy: {
      "/api": "http://127.0.0.1:3000"
    }
  },
  build: {
    outDir: resolve(projectRoot, "dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        portfolio: resolve(clientRoot, "index.html"),
        admin: resolve(clientRoot, "admin/index.html")
      }
    }
  }
}));