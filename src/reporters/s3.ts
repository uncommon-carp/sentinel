import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

export async function uploadReportToS3(
  resultsBucket: string,
  runId: string,
  report: unknown
): Promise<void> {
  const endpointUrl = process.env.AWS_ENDPOINT_URL;

  const client = new S3Client({
    region: process.env.AWS_REGION ?? 'us-east-1',
    ...(endpointUrl ? { endpoint: endpointUrl, forcePathStyle: true } : {})
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
