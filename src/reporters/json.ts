import type { Reporter, RunResult } from '../core/types.js';

export function jsonReporter(): Reporter {
  return {
    name: 'json',
    render(result: RunResult): string {
      return JSON.stringify(result, null, 2);
    }
  };
}
