import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    include: ["test/**/*.test.ts"],
    restoreMocks: true,
    mockReset: true,
    clearMocks: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/cli/**"],   // CLI entry points are smoke-tested, not unit-tested
      thresholds: {
        statements: 90,
        branches: 78,
        functions: 95,
        lines: 93
      }
    }
  }
});
