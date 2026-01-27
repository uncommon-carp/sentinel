export type ApiEndpoint = {
  method: string; // lowercase: get/post/put/...
  path: string; // as in spec, e.g. "/users/{id}"
};

export type LoadedApiSpec = {
  source: string; // file path or URL
  spec: Record<string, unknown>; // dereferenced object
  endpoints: ApiEndpoint[];
};
