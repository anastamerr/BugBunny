import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"

// https://vite.dev/config/
const reactPlugin = react() as any

export default defineConfig({
  plugins: [reactPlugin],
  server: {
    host: true,
    port: 3000,
  },
  test: {
    environment: "happy-dom",
    setupFiles: "./src/test/setup.ts",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    exclude: ["tests/e2e/**", "node_modules/**"],
  },
})
