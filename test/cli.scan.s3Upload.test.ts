import { describe, it, expect, vi } from 'vitest';

const { mockUploadReportToS3 } = vi.hoisted(() => ({
  mockUploadReportToS3: vi.fn()
}));

vi.mock('../src/reporters/s3.js', () => ({
  uploadReportToS3: mockUploadReportToS3
}));

import { uploadPipelineReport } from '../src/cli/commands/scan.js';
import type { RunResult } from '../src/core/types.js';
import type { Logger } from '../src/core/logger.js';

function makeResult(): RunResult {
  return {
    meta: {
      startedAt: '2026-01-01T00:00:00Z',
      targetBaseUrl: 'http://localhost:3000',
      version: '0.4.0'
    },
    config: {},
    findings: [],
    suiteErrors: [],
    reporterErrors: []
  };
}

function makeLogger(): Logger {
  return { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
}

const pipeline = { resultsBucket: 'my-bucket', runId: 'run-abc' };

describe('uploadPipelineReport', () => {
  it('uploads and logs success, leaving reporterErrors empty', async () => {
    mockUploadReportToS3.mockResolvedValue(undefined);
    const result = makeResult();
    const logger = makeLogger();

    await uploadPipelineReport(pipeline, result, logger);

    expect(mockUploadReportToS3).toHaveBeenCalledWith('my-bucket', 'run-abc', result);
    expect(result.reporterErrors).toEqual([]);
    expect(logger.info).toHaveBeenCalledWith(
      expect.stringContaining('s3://my-bucket/results/run-abc.json'),
      expect.objectContaining({ event: 'sentinel.s3.uploaded' })
    );
  });

  // Regression (7.3): a failed upload on an otherwise-complete scan must not
  // throw — before the fix, this call was unwrapped in scanCommand and the
  // rejection propagated to cli/index.ts's top-level handler, reporting exit
  // code 3 ("fatal pre-scan error") even though the scan had already finished.
  it('does not throw when the upload fails, and records it in reporterErrors instead', async () => {
    mockUploadReportToS3.mockRejectedValue(new Error('NoSuchBucket'));
    const result = makeResult();
    const logger = makeLogger();

    await expect(uploadPipelineReport(pipeline, result, logger)).resolves.toBeUndefined();

    expect(result.reporterErrors).toEqual([
      expect.objectContaining({ reporter: 's3', message: 'NoSuchBucket' })
    ]);
    expect(logger.error).toHaveBeenCalledWith(
      expect.stringContaining('NoSuchBucket'),
      expect.objectContaining({ event: 'sentinel.s3.upload.error' })
    );
    expect(logger.info).not.toHaveBeenCalled();
  });

  it('handles a thrown non-Error value without crashing', async () => {
    mockUploadReportToS3.mockRejectedValue('timeout string, not an Error object');
    const result = makeResult();
    const logger = makeLogger();

    await uploadPipelineReport(pipeline, result, logger);

    expect(result.reporterErrors).toEqual([
      expect.objectContaining({ reporter: 's3', message: 'timeout string, not an Error object' })
    ]);
  });
});
