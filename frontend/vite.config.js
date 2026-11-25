import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

function validateApiOrigin(value) {
  let apiUrl;
  try {
    apiUrl = new URL(value);
  } catch {
    throw new Error("VITE_API_BASE_URL must be a valid public HTTPS API origin.");
  }
  if (
    apiUrl.protocol !== "https:"
    || !apiUrl.hostname
    || apiUrl.username
    || apiUrl.password
    || apiUrl.pathname !== "/"
    || apiUrl.search
    || apiUrl.hash
  ) {
    throw new Error("VITE_API_BASE_URL must be an HTTPS origin without credentials, path, query, or fragment.");
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBaseUrl = process.env.VITE_API_BASE_URL || env.VITE_API_BASE_URL;
  const sameOrigin = (process.env.VITE_SAME_ORIGIN_API || env.VITE_SAME_ORIGIN_API) === "true";

  if (mode === "production") {
    if (apiBaseUrl) {
      validateApiOrigin(apiBaseUrl);
    } else if (!sameOrigin) {
      // Production must state explicitly how the browser reaches the API:
      // either an HTTPS API origin, or a same-origin reverse proxy (e.g. Vercel rewrites).
      throw new Error(
        "Set VITE_API_BASE_URL to the public HTTPS API URL, or VITE_SAME_ORIGIN_API=true when /api/v1 is proxied.",
      );
    }
  }

  return {
    plugins: [react(), tailwindcss()],
    build: {
      rollupOptions: {
        input: {
          main: resolve(import.meta.dirname, "index.html"),
          legacy: resolve(import.meta.dirname, "legacy.html"),
        },
      },
    },
    server: {
      proxy: {
        // Multi-tenant platform API keeps its /api/v1 prefix.
        "/api/v1": { target: "http://127.0.0.1:8000" },
        // Legacy console API is mounted at the backend root.
        "/api": {
          target: "http://127.0.0.1:8000",
          rewrite: (path) => path.replace(/^\/api/, ""),
        },
      },
    },
    test: {
      environment: "jsdom",
      include: ["test-app/**/*.test.{ts,tsx}"],
      setupFiles: ["test-app/setup.ts"],
      css: false,
    },
  };
});
