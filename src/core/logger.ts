export type DebugEvent =
  | 'sentinel.scan_start'
  | 'sentinel.scan_complete'
  | 'http.request'
  | 'http.response'
  | 'cors.probe'
  | 'auth.probe'
  | 'auth.jwt_inspected'
  | 'ratelimit.probe'
  | 'ratelimit.burst.start'
  | 'ratelimit.burst.request'
  | 'ratelimit.burst.throttled'
  | 'injection.probe'
  | 'inventory.probe'
  | 'headers.check';

export type Logger = {
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
  debug(msg: string, data?: { event: DebugEvent } & Record<string, unknown>): void;
};

export function createLogger(opts: { verbose: boolean }): Logger {
  const emit = (level: string, msg: string, data?: Record<string, unknown>) => {
    const payload = data ? ` ${JSON.stringify(data)}` : '';
    console.log(`[${level}] ${msg}${payload}`);
  };

  return {
    info: (m, d) => emit('INFO', m, d),
    warn: (m, d) => emit('WARN', m, d),
    error: (m, d) => emit('ERROR', m, d),
    debug: (m, d) => {
      if (opts.verbose) emit('DEBUG', m, d);
    }
  };
}
