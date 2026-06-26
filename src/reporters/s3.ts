import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

export async function uploadReportToS3(
  resultsBucket: string,
  runId: string,
  report: unknown
): Promise<void> {
  const client = new S3Client({});
  await client.send(
    new PutObjectCommand({
      Bucket: resultsBucket,
      Key: `results/${runId}.json`,
      Body: JSON.stringify(report),
      ContentType: 'application/json'
    })
  );
}
