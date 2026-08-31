import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["packages/*/src/**/*.test.ts"],
    // The secret-leak tests inspect process output and rely on module state
    // being fresh; isolation is cheap here and the suite is small.
    isolate: true,
  },
});
