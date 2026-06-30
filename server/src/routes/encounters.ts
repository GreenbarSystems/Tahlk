import type { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { prisma } from '../db.js';
import { uploadPdf, getSignedDownloadUrl } from '../services/s3Service.js';

const ArchivePdfSchema = z.object({
  // base64-encoded PDF rendered client-side via jsPDF
  pdfBase64:     z.string().min(100),
  // YYYY-MM-DD — used in the S3 key for human readability
  encounterDate: z.string().optional(),
});

export const encounterRoutes: FastifyPluginAsync = async (app) => {
  // POST /api/encounters/:id/archive-pdf
  //
  // The client renders the PDF locally (zero-knowledge — we never see plaintext note
  // content during this request) and sends the pre-rendered binary as base64.
  // We upload to S3 with SSE-S3 encryption, stamp the encounter row, and write an
  // immutable AuditLog entry recording who archived what and when.
  app.post('/:id/archive-pdf', async (req, reply) => {
    const { id } = req.params as { id: string };
    const parsed = ArchivePdfSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { orgId, sub: providerId } = req.provider!;

    const encounter = await prisma.encounter.findFirst({
      where:  { id, orgId },
      select: { id: true, signedAt: true, pdfS3Key: true },
    });
    if (!encounter) return reply.code(404).send({ error: 'Encounter not found' });

    const pdfBuf = Buffer.from(parsed.data.pdfBase64, 'base64');
    if (pdfBuf.byteLength < 500) {
      return reply.code(400).send({ error: 'PDF payload too small — upload may be corrupt' });
    }

    const dateStr = (parsed.data.encounterDate ?? new Date().toISOString())
      .slice(0, 10)
      .replace(/-/g, '');
    const s3Key = `orgs/${orgId}/encounters/${id}/${dateStr}_note.pdf`;

    try {
      await uploadPdf(s3Key, pdfBuf);
    } catch (err: any) {
      req.log.error({ err }, 's3 upload failed');
      return reply.code(502).send({ error: err.message ?? 'S3 upload failed' });
    }

    await prisma.$transaction([
      prisma.encounter.update({
        where: { id },
        data:  { pdfS3Key: s3Key },
      }),
      prisma.auditLog.create({
        data: {
          orgId,
          providerId,
          encounterId: id,
          action:    'pdf_archived',
          meta: {
            s3Key,
            sizeBytes:      pdfBuf.byteLength,
            isSigned:       !!encounter.signedAt,
            replacedPrior:  !!encounter.pdfS3Key,
          },
          ipAddress: req.ip,
        },
      }),
    ]);

    return { pdfS3Key: s3Key };
  });

  // GET /api/encounters/:id/pdf-url
  //
  // Returns a 30-minute pre-signed S3 URL so the client can open the archived PDF
  // in the system browser without exposing a permanent link. Every access is logged.
  app.get('/:id/pdf-url', async (req, reply) => {
    const { id } = req.params as { id: string };
    const { orgId, sub: providerId } = req.provider!;

    const encounter = await prisma.encounter.findFirst({
      where:  { id, orgId },
      select: { id: true, pdfS3Key: true },
    });
    if (!encounter)           return reply.code(404).send({ error: 'Encounter not found' });
    if (!encounter.pdfS3Key) return reply.code(404).send({ error: 'No archived PDF for this encounter' });

    let url: string;
    try {
      url = await getSignedDownloadUrl(encounter.pdfS3Key);
    } catch (err: any) {
      req.log.error({ err }, 's3 presign failed');
      return reply.code(502).send({ error: err.message ?? 'Could not generate download URL' });
    }

    await prisma.auditLog.create({
      data: {
        orgId,
        providerId,
        encounterId: id,
        action:    'pdf_url_requested',
        meta: { s3Key: encounter.pdfS3Key },
        ipAddress: req.ip,
      },
    });

    return { url, expiresInSec: 1800 };
  });
};
