// HIPAA bucket requirements (set once in the AWS console or IaC):
//   • Block all public access: ON
//   • Versioning: enabled (retains overwritten/deleted objects)
//   • Object Lock: ON in Governance mode (optional — prevents deletion for retention period)
//   • Server access logging: enabled (separate bucket)
//   • Default encryption: SSE-S3 (AES-256) — redundant with our PutObject setting but good defense-in-depth
//
// IAM policy for the server's credentials should allow only:
//   s3:PutObject, s3:GetObject on arn:aws:s3:::BUCKET/orgs/*

import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const REGION = process.env.AWS_REGION ?? 'us-east-1';
const BUCKET = process.env.AWS_S3_BUCKET;

// Lazily initialised so the server starts cleanly when AWS vars aren't configured;
// calls throw a clear error only if a PDF archive is actually requested.
let _s3: S3Client | null = null;

function s3Client(): S3Client {
  if (!_s3) {
    if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY || !BUCKET) {
      throw new Error(
        'AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET must be set to archive PDFs',
      );
    }
    _s3 = new S3Client({
      region: REGION,
      credentials: {
        accessKeyId:     process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      },
    });
  }
  return _s3;
}

// Upload a PDF buffer. Content-Disposition=inline so pre-signed URLs open in-browser.
// SSE-S3 (AES-256) provides encryption at rest independently of bucket default.
export async function uploadPdf(key: string, pdfBuffer: Buffer): Promise<void> {
  await s3Client().send(
    new PutObjectCommand({
      Bucket:               BUCKET!,
      Key:                  key,
      Body:                 pdfBuffer,
      ContentType:          'application/pdf',
      ContentDisposition:   'inline',
      ServerSideEncryption: 'AES256',
    }),
  );
}

// Returns a 30-minute (default) pre-signed GET URL for a stored PDF.
export async function getSignedDownloadUrl(key: string, expiresInSec = 1800): Promise<string> {
  return getSignedUrl(
    s3Client(),
    new GetObjectCommand({ Bucket: BUCKET!, Key: key }),
    { expiresIn: expiresInSec },
  );
}
