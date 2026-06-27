import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { mockSend, MockS3Client, MockPutObjectCommand } = vi.hoisted(() => {
  const mockSend = vi.fn();
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
    delete process.env.AWS_ENDPOINT_URL;
    delete process.env.AWS_REGION;
  });

  afterEach(() => {
    delete process.env.AWS_ENDPOINT_URL;
    delete process.env.AWS_REGION;
  });

  it('production mode — no endpoint override when AWS_ENDPOINT_URL is absent', async () => {
    const report = { meta: { version: '0.4.0' }, findings: [] };
    await uploadReportToS3('my-bucket', 'run-abc', report);

    expect(MockS3Client).toHaveBeenCalledWith({
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

  it('local mode — endpoint and forcePathStyle set when AWS_ENDPOINT_URL is present', async () => {
    process.env.AWS_ENDPOINT_URL = 'http://localstack:4566';
    process.env.AWS_REGION = 'us-east-1';

    await uploadReportToS3('my-bucket', 'run-abc', {});

    expect(MockS3Client).toHaveBeenCalledWith({
      region: 'us-east-1',
      endpoint: 'http://localstack:4566',
      forcePathStyle: true
    });
  });

  it('uses the task IAM role — no explicit credentials in constructor', async () => {
    await uploadReportToS3('bucket', 'run-id', {});
    const [[constructorArg]] = MockS3Client.mock.calls;
    expect(constructorArg).not.toHaveProperty('credentials');
    expect(constructorArg).not.toHaveProperty('accessKeyId');
  });

  it('propagates S3 errors', async () => {
    mockSend.mockRejectedValue(new Error('NoSuchBucket'));
    await expect(uploadReportToS3('bad-bucket', 'run-id', {})).rejects.toThrow('NoSuchBucket');
  });
});
