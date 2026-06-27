import { describe, it, expect, vi, beforeEach } from 'vitest';

const { mockSend, MockS3Client, MockPutObjectCommand } = vi.hoisted(() => {
  const mockSend = vi.fn();
  // Must be a regular function (not arrow) to work as a constructor via `new`
  const MockS3Client = vi.fn(function (this: Record<string, unknown>) {
    this['send'] = mockSend;
  });
  const MockPutObjectCommand = vi.fn(function (this: Record<string, unknown>, input: unknown) {
    Object.assign(this as object, input as object);
  });
  return { mockSend, MockS3Client, MockPutObjectCommand };
});

vi.mock('@aws-sdk/client-s3', () => ({
  S3Client: MockS3Client,
  PutObjectCommand: MockPutObjectCommand
}));

import { uploadReportToS3 } from '../src/reporters/s3.js';

describe('reporters/s3', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSend.mockResolvedValue({});
  });

  it('sends a PutObjectCommand with the correct params', async () => {
    const report = { meta: { version: '0.3.2' }, findings: [] };
    await uploadReportToS3('my-bucket', 'run-abc', report);

    expect(MockS3Client).toHaveBeenCalledWith({
      endpoint: '',
      forcePathStyle: true,
      region: 'us-east-1'
    });
    expect(MockPutObjectCommand).toHaveBeenCalledWith({
      Bucket: 'my-bucket',
      Key: 'results/run-abc.json',
      Body: JSON.stringify(report),
      ContentType: 'application/json'
    });
    expect(mockSend).toHaveBeenCalledOnce();
  });

  it('uses the task IAM role (no explicit credentials)', async () => {
    await uploadReportToS3('bucket', 'run-id', {});
    const [[constructorArg]] = MockS3Client.mock.calls;
    expect(constructorArg).toEqual({
      endpoint: '',
      forcePathStyle: true,
      region: 'us-east-1'
    });
  });

  it('propagates S3 errors', async () => {
    mockSend.mockRejectedValue(new Error('NoSuchBucket'));
    await expect(uploadReportToS3('bad-bucket', 'run-id', {})).rejects.toThrow('NoSuchBucket');
  });
});
