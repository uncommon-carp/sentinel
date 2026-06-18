import { describe, it, expect, vi, afterEach } from 'vitest';
import { createLogger } from '../src/core/logger.js';

describe('createLogger', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('always emits info, warn, and error regardless of verbose', () => {
    const logger = createLogger({ verbose: false });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.info('info message');
    logger.warn('warn message');
    logger.error('error message');

    expect(spy).toHaveBeenCalledTimes(3);
  });

  it('suppresses debug when verbose is false', () => {
    const logger = createLogger({ verbose: false });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.debug('debug message');

    expect(spy).not.toHaveBeenCalled();
  });

  it('emits debug when verbose is true', () => {
    const logger = createLogger({ verbose: true });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.debug('debug message');

    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('prefixes output with the log level', () => {
    const logger = createLogger({ verbose: true });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.info('hello');
    logger.warn('hello');
    logger.error('hello');
    logger.debug('hello');

    expect(spy).toHaveBeenNthCalledWith(1, '[INFO] hello');
    expect(spy).toHaveBeenNthCalledWith(2, '[WARN] hello');
    expect(spy).toHaveBeenNthCalledWith(3, '[ERROR] hello');
    expect(spy).toHaveBeenNthCalledWith(4, '[DEBUG] hello');
  });

  it('includes structured data as JSON in the output', () => {
    const logger = createLogger({ verbose: true });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.debug('probing endpoint', { event: 'http.request', url: '/foo' });

    expect(spy).toHaveBeenCalledWith(
      '[DEBUG] probing endpoint {"event":"http.request","url":"/foo"}'
    );
  });

  it('omits the data payload entirely when none is provided', () => {
    const logger = createLogger({ verbose: true });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.debug('no data here');

    expect(spy).toHaveBeenCalledWith('[DEBUG] no data here');
  });

  it('serializes empty data objects rather than omitting them', () => {
    const logger = createLogger({ verbose: true });
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});

    logger.info('empty data', {});

    expect(spy).toHaveBeenCalledWith('[INFO] empty data {}');
  });
});
