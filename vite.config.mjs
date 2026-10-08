import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { defineConfig } from "vite";

const projectRoot = fileURLToPath(new URL(".", import.meta.url));
const clientRoot = resolve(projectRoot, "client");

export default defineConfig(({ mode }) => ({
  root: clientRoot,
  // Keep assets rooted at the site origin so nested SPA routes such as
  // /certificate/7 never resolve scripts and styles under /certificate/.
  base: "/",
  publicDir: resolve(projectRoot, "public"),
  server: {
    proxy: {
      "/api": mode === "remote-preview" ? {
        target: "https://kqdrhwdidjrdbmwteuom.supabase.co",
        changeOrigin: true,
        headers: { apikey: "sb_publishable_Nmyw4pDaqtHNTfuYCmoA3A_aFgn8tZ3" },
        rewrite: path => `/functions/v1/portfolio-api?path=${encodeURIComponent(path)}`
      } : "http://127.0.0.1:3000"
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
