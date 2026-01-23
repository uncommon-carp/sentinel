/**
 * HttpClient
 *
 * A thin, opinionated wrapper around `fetch` used by all Sentinel suites.
 *
 * Responsibilities:
 * - Normalize request construction (base URL + relative paths)
 * - Inject auth and default headers consistently
 * - Enforce timeouts via AbortController
 * - Return a simplified, deterministic response shape for suites
 *
 * Design notes:
 * - This is intentionally *not* a full HTTP abstraction.
 * - Retries, backoff, and concurrency limits should be applied at the
 *   runner or suite level, not here.
 * - Suites should treat this client as untrusted I/O and keep logic
 *   side-effect free and deterministic.
 */

export type HttpRequest = {
  method: string;
  path?: string;
  url?: string;
  headers?: Record<string, string>;
  body?: string;
};

export type HttpResponse = {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  url: string;
};

export type HttpClientOptions = {
  baseUrl: string;
  defaultHeaders?: Record<string, string>;
  timeoutMs: number;
  authHeader?: () => Record<string, string>;
};

function headersToRecord(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

export class HttpClient {
  constructor(private opts: HttpClientOptions) { }

  async request(req: HttpRequest): Promise<HttpResponse> {
    const url = req.url ?? new URL(req.path ?? "/", this.opts.baseUrl).toString();

    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), this.opts.timeoutMs);

    try {
      const headers: Record<string, string> = {
        ...(this.opts.defaultHeaders ?? {}),
        ...(this.opts.authHeader ? this.opts.authHeader() : {}),
        ...(req.headers ?? {})
      };

      const init: RequestInit = {
        method: req.method,
        headers,
        signal: controller.signal,
        ...(req.body !== undefined ? { body: req.body } : {})
      };

      const res = await fetch(url, init);


      const bodyText = await res.text();
      return {
        status: res.status,
        headers: headersToRecord(res.headers),
        bodyText,
        url
      };
    } finally {
      clearTimeout(t);
    }
  }
}
