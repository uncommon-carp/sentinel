import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

export async function uploadReportToS3(
  resultsBucket: string,
  runId: string,
  report: unknown
): Promise<void> {
  const client = new S3Client({
    forcePathStyle: true,
    endpoint: process.env.AWS_ENDPOINT_URL ?? '',
    region: process.env.AWS_REGION ?? 'us-east-1'
  });

  await client.send(
    new PutObjectCommand({
      Bucket: resultsBucket,
      Key: `results/${runId}.json`,
      Body: JSON.stringify(report),
      ContentType: 'application/json'
    })
  );
}
