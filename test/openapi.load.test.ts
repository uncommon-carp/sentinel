
import { describe, it, expect } from "vitest";
import path from "node:path";
import { loadOpenApi } from "../src/openapi/load.js";

describe("openapi/load", () => {
  it("loads a local spec and extracts endpoints", async () => {
    const source = path.resolve("test/fixtures/openapi.min.json");
    const loaded = await loadOpenApi(source);

    expect(loaded.source).toBe(source);
    expect(Array.isArray(loaded.endpoints)).toBe(true);

    // Exact set (order doesn't matter)
    const set = new Set(loaded.endpoints.map((e) => `${e.method} ${e.path}`));

    expect(set.has("get /")).toBe(true);
    expect(set.has("get /users/{id}")).toBe(true);
    expect(set.has("delete /users/{id}")).toBe(true);
    expect(set.has("head /health")).toBe(true);
  });

  it("throws a readable error for invalid spec input", async () => {
    const source = path.resolve("test/fixtures/openapi.invalid.txt");
    await expect(loadOpenApi(source)).rejects.toThrow(/Failed to parse OpenAPI spec/i);
  });
});
