// Clinical note PDF export — runs entirely in the Tauri webview (no cloud).
// Uses jsPDF for layout; binary output is saved via a Rust file-dialog command.

import { jsPDF } from 'jspdf';
import { appendAudit }        from '../core/auditLog.js';
import { emit }               from '../core/eventBus.js';
import { kvGet, kvSet, tauriInvoke } from '../core/storageBackend.js';
import { apiFetch }           from '../core/api.js';

const PAGE_W    = 612;   // US Letter, points
const PAGE_H    = 792;
const MARGIN    = 72;    // 1 inch
const CONTENT_W = PAGE_W - MARGIN * 2;   // 468 pt

const NAVY  = [17, 40, 77];
const GREEN = [45, 156, 92];
const GRAY  = [107, 114, 128];
const INK   = [20, 20, 20];

const ARCHIVE_S3_KEY   = id => `note_archive_v1::${id}::s3_key`;
const ARCHIVE_DATE_KEY = id => `note_archive_v1::${id}::archived_at`;

// ── Public ────────────────────────────────────────────────────────────────────

// Returns cached archive status from KV — no network call.
export function getLocalArchiveStatus(encounterId) {
  return {
    s3Key:      kvGet(ARCHIVE_S3_KEY(encounterId))   ?? null,
    archivedAt: kvGet(ARCHIVE_DATE_KEY(encounterId)) ?? null,
  };
}

// Builds the PDF locally and uploads it to Tahlk Cloud (S3 via the server).
// The server never receives plaintext note content — only the pre-rendered PDF bytes.
// Returns the S3 key on success; throws on error.
export async function archiveToCloud(note, encounter, provider) {
  const buf    = _buildPdf(note, encounter, provider);
  const base64 = _bufToBase64(buf);

  const res = await apiFetch(`/api/encounters/${encounter.id}/archive-pdf`, {
    method: 'POST',
    body:   JSON.stringify({
      pdfBase64:     base64,
      encounterDate: encounter.encounter_date,
    }),
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Archive failed (${res.status})`);
  }

  const { pdfS3Key } = await res.json();

  kvSet(ARCHIVE_S3_KEY(encounter.id), pdfS3Key);
  kvSet(ARCHIVE_DATE_KEY(encounter.id), new Date().toISOString());

  appendAudit(`note_audit_v1::${encounter.id}`, 'pdf_archived_cloud', { pdfS3Key });
  emit('scribe:note_archived', { encounterId: encounter.id, pdfS3Key });

  return pdfS3Key;
}

// Fetches a 30-minute pre-signed S3 download URL from the server.
// Every call is logged server-side (HIPAA audit trail for PHI access).
export async function getCloudPdfUrl(encounterId) {
  const res = await apiFetch(`/api/encounters/${encounterId}/pdf-url`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Could not get PDF URL (${res.status})`);
  }
  const { url } = await res.json();
  return url;
}

export async function saveToPdf(note, encounter, provider) {
  const buf          = _buildPdf(note, encounter, provider);
  const base64       = _bufToBase64(buf);
  const date         = (encounter.encounter_date || '').slice(0, 10).replace(/-/g, '');
  const aliasPart    = encounter.patient_alias
    ? `_${encounter.patient_alias.replace(/[^a-zA-Z0-9]/g, '-')}`
    : '';
  const suggestedName = `note_${date}${aliasPart}.pdf`;

  await tauriInvoke('export_pdf_file', { data: base64, suggestedName });

  appendAudit(`note_audit_v1::${encounter.id}`, 'note_exported', { format: 'pdf', method: 'file' });
  emit('scribe:note_exported', { encounterId: encounter.id, format: 'pdf' });
}

// ── PDF builder ───────────────────────────────────────────────────────────────

function _buildPdf(note, encounter, provider) {
  const doc = new jsPDF({ unit: 'pt', format: 'letter', compress: true });

  let y = MARGIN;

  // Header (page 1)
  y = _header(doc, y, encounter, provider);

  // Note body — paginate
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10.5);
  doc.setTextColor(...INK);

  const lines = doc.splitTextToSize(note || '(No note content)', CONTENT_W);
  for (const line of lines) {
    if (y > PAGE_H - MARGIN - 56) {
      doc.addPage();
      y = MARGIN;
    }
    doc.text(line, MARGIN, y);
    y += 14.5;
  }

  // Footer on every page
  const total = doc.internal.getNumberOfPages();
  for (let p = 1; p <= total; p++) {
    doc.setPage(p);
    _footer(doc, encounter, provider, p, total);
  }

  return doc.output('arraybuffer');
}

function _header(doc, y, encounter, provider) {
  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(20);
  doc.setTextColor(...NAVY);
  doc.text('CLINICAL NOTE', MARGIN, y);

  // Brand tag (right-aligned, same baseline)
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(9);
  doc.setTextColor(...GREEN);
  doc.text('Tahlk', PAGE_W - MARGIN, y, { align: 'right' });
  y += 8;

  // Navy rule
  doc.setDrawColor(...NAVY);
  doc.setLineWidth(1.5);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);
  y += 16;

  // Provider info
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(...GRAY);
  const providerLine = [provider.name, provider.credentials].filter(Boolean).join(', ');
  if (providerLine) { doc.text(providerLine, MARGIN, y); y += 13; }
  if (provider.specialty) { doc.text(_specialtyLabel(provider.specialty), MARGIN, y); y += 13; }
  y += 6;

  // Encounter metadata
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(...INK);
  doc.text(`Date of Service: ${encounter.encounter_date || ''}`, MARGIN, y); y += 15;
  if (encounter.patient_alias) { doc.text(`Patient: ${encounter.patient_alias}`, MARGIN, y); y += 15; }
  doc.text(`Encounter ID: ${encounter.id}`, MARGIN, y); y += 15;

  // Signed / Draft badge
  const signed = encounter.status === 'signed';
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  if (signed) {
    doc.setTextColor(...GREEN);
    doc.text('✓  SIGNED AND ATTESTED', MARGIN, y);
  } else {
    doc.setTextColor(210, 50, 50);
    doc.text('DRAFT — Not yet signed', MARGIN, y);
  }
  y += 22;

  // Light rule before body
  doc.setDrawColor(210, 215, 220);
  doc.setLineWidth(0.5);
  doc.line(MARGIN, y, PAGE_W - MARGIN, y);
  y += 18;

  return y;
}

function _footer(doc, encounter, provider, pageNum, total) {
  const fy = PAGE_H - MARGIN + 16;

  doc.setDrawColor(210, 215, 220);
  doc.setLineWidth(0.5);
  doc.line(MARGIN, fy - 14, PAGE_W - MARGIN, fy - 14);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);

  // Left: signature line or draft warning
  if (encounter.status === 'signed' && encounter.signed_at) {
    const when = new Date(encounter.signed_at).toLocaleString();
    doc.setTextColor(...GRAY);
    doc.text(`Signed & attested by ${provider.name || 'Provider'} — ${when}`, MARGIN, fy);
    if (encounter.signed_hash) {
      doc.setFontSize(6.5);
      doc.text(`SHA-256: ${encounter.signed_hash}`, MARGIN, fy + 10);
    }
  } else {
    doc.setTextColor(200, 70, 70);
    doc.text('DRAFT — Provider review and sign-off required before use', MARGIN, fy);
  }

  // Center: product name
  doc.setTextColor(...GRAY);
  doc.setFontSize(7.5);
  doc.text('Tahlk Ambient Scribe', PAGE_W / 2, fy, { align: 'center' });

  // Right: page number
  doc.text(`${pageNum} / ${total}`, PAGE_W - MARGIN, fy, { align: 'right' });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _specialtyLabel(s) {
  return {
    psychiatry: 'Psychiatry',
    'behavioral-health': 'Behavioral Health / Therapy',
    psychology: 'Psychology',
    podiatry:   'Podiatry',
    other:      'Other',
  }[s] || s;
}

function _bufToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
