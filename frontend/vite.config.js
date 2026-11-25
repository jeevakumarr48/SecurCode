import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiBaseUrl = process.env.VITE_API_BASE_URL || env.VITE_API_BASE_URL;

  if (mode === "production") {
    if (!apiBaseUrl) {
      throw new Error("Set VITE_API_BASE_URL to the public HTTPS API URL before building for production.");
    }
    let apiUrl;
    try {
      apiUrl = new URL(apiBaseUrl);
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
      throw new Error(
        "VITE_API_BASE_URL must be an HTTPS origin without credentials, path, query, or fragment.",
      );
    }
  }

  return {
    plugins: [react()],
    server: {
      proxy: {
        "/api": {
          target: "http://127.0.0.1:8000",
          rewrite: (path) => path.replace(/^\/api/, ""),
        },
      },
    },
  };
});
