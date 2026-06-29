// Unit tests for the UI kit. Pure functions -> assert on rendered markup,
// escaping, and accessibility attributes. Also serve as living usage examples.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Button, Field, StatusChip, StatCard, EmptyState, ProgressBar, Banner, html, raw,
} from '../../src/ui/index.js';

test('Button renders label, variant, and size classes', () => {
  const out = Button({ label: 'Save', variant: 'primary', size: 'lg' });
  assert.match(out, /class="ui-btn ui-btn--primary ui-btn--lg"/);
  assert.match(out, />.*Save.*<\/button>/s);
});

test('Button loading state disables and announces busy', () => {
  const out = Button({ label: 'Save', loading: true });
  assert.match(out, /disabled/);
  assert.match(out, /aria-busy="true"/);
  assert.match(out, /ui-btn__spinner/);
});

test('Button escapes its label', () => {
  const out = Button({ label: '<script>alert(1)</script>' });
  assert.doesNotMatch(out, /<script>/);
  assert.match(out, /&lt;script&gt;/);
});

test('Field associates label with control and wires describedby', () => {
  const out = Field({ id: 'f1', label: 'Name', hint: 'Full name', error: 'Required' });
  assert.match(out, /<label[^>]*for="f1"/);
  assert.match(out, /id="f1"/);
  assert.match(out, /aria-invalid="true"/);
  assert.match(out, /aria-describedby="f1-hint f1-err"/);
  assert.match(out, /role="alert"/);
});

test('Field select marks the selected option', () => {
  const out = Field({
    label: 'Specialty', type: 'select', value: 'psych',
    options: [{ value: 'psych', label: 'Psychiatry' }, { value: 'other', label: 'Other' }],
  });
  assert.match(out, /<option value="psych" selected>Psychiatry<\/option>/);
});

test('StatusChip maps status to tone + label', () => {
  assert.match(StatusChip({ status: 'signed' }), /ui-chip--success/);
  assert.match(StatusChip({ status: 'signed' }), />Signed</);
});

test('StatCard exposes a combined aria-label', () => {
  assert.match(StatCard({ value: 12, label: 'Signed' }), /aria-label="12 Signed"/);
});

test('EmptyState renders title and optional action button', () => {
  const out = EmptyState({ title: 'Nothing here', action: { id: 'go', label: 'Start' } });
  assert.match(out, /Nothing here/);
  assert.match(out, /id="go"/);
});

test('ProgressBar clamps value and sets aria range', () => {
  const out = ProgressBar({ value: 1.5, label: 'Download' });
  assert.match(out, /role="progressbar"/);
  assert.match(out, /aria-valuenow="100"/);
  assert.match(out, /width:100%/);
});

test('Banner uses role=alert for errors, role=status otherwise', () => {
  assert.match(Banner({ kind: 'error', message: 'x' }), /role="alert"/);
  assert.match(Banner({ kind: 'success', message: 'x' }), /role="status"/);
});

test('html tag escapes interpolations but trusts raw()', () => {
  const out = html`<p>${'<b>x</b>'} ${raw('<i>ok</i>')}</p>`;
  assert.match(out, /&lt;b&gt;x&lt;\/b&gt;/);
  assert.match(out, /<i>ok<\/i>/);
});
