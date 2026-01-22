import { vi } from "vitest";

type MockedFetchResponse = {
  status: number;
  headers?: Record<string, string>;
  bodyText?: string;
};

function makeHeaders(headers: Record<string, string>) {
  // Minimal Headers-like object for our usage (res.headers.forEach)
  const entries = Object.entries(headers);
  return {
    forEach(cb: (value: string, key: string) => void) {
      for (const [k, v] of entries) cb(v, k);
    }
  } as unknown as Headers;
}

export function mockFetchOnce(resp: MockedFetchResponse) {
  const status = resp.status;
  const headers = makeHeaders(resp.headers ?? {});
  const bodyText = resp.bodyText ?? "";

  const fetchMock = vi.fn(async () => {
    return {
      status,
      headers,
      text: async () => bodyText
    } as unknown as Response;
  });

  // Attach to global fetch
  vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);

  return fetchMock;
}
