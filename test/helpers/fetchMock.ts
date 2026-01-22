import { vi } from "vitest";

type MockedFetchResponse = {
  status: number;
  headers?: Record<string, string>;
  bodyText?: string;
};

function makeHeaders(headers: Record<string, string>) {
  const entries = Object.entries(headers);
  return {
    forEach(cb: (value: string, key: string) => void) {
      for (const [k, v] of entries) cb(v, k);
    }
  } as unknown as Headers;
}

export function mockFetchQueue(responses: MockedFetchResponse[]) {
  const queue = [...responses];

  const fetchMock = vi.fn(async () => {
    const next = queue.shift();
    if (!next) throw new Error("mockFetchQueue: no more mocked responses in queue");

    return {
      status: next.status,
      headers: makeHeaders(next.headers ?? {}),
      text: async () => next.bodyText ?? ""
    } as unknown as Response;
  });

  vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
  return fetchMock;
}

