// Patient consent-to-record capture (finding S1).
//
// Before an encounter is recorded, the provider must attest that the patient
// consented to being recorded. In all-party-consent (wiretap) states, recording
// a confidential conversation without every party's consent can be a CRIMINAL
// violation, so in those states the copy names the requirement and the
// attestation is the legal predicate for recording — not a nicety.
//
// Built on the shared modal shell (platform/modal.js), like confirmModal.js.
// Nodes are built explicitly (no innerHTML) so the state label can't inject
// markup and the dialog stays drivable in the fake-DOM tests. Resolves `true`
// only when the provider checks the attestation box AND confirms; `false` on
// cancel, Escape, or backdrop click (fail safe: no attestation, no recording).

import { createModal } from '../platform/modal.js';

export function consentToRecordModal({ allParty = true, stateLabel = '' } = {}) {
  return new Promise(resolve => {
    let settled = false;
    const settle = result => {
      if (settled) return;
      settled = true;
      modal.close();
      resolve(result);
    };

    const modal = createModal({
      backdropId: 'modal-backdrop',
      onRequestClose: () => settle(false),
    });
    const { card } = modal;

    const heading = document.createElement('h2');
    heading.className = 'modal-title';
    heading.id = 'modal-title';
    heading.textContent = 'Patient consent to record';

    const body = document.createElement('p');
    body.className = 'modal-message';
    body.id = 'modal-message';
    const where = stateLabel || 'Your state';
    body.textContent = allParty
      ? `${where} requires ALL parties to consent before a conversation is recorded. `
        + 'Confirm the patient has been informed and agreed to this session being recorded. '
        + 'Recording without consent may be unlawful.'
      : 'Confirm the patient has been informed and consents to this session being recorded.';

    const attest = document.createElement('label');
    attest.className = 'consent-attest';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.id = 'consent-attest-box';
    const span = document.createElement('span');
    span.textContent = "I have obtained the patient's consent to record this encounter.";
    attest.appendChild(box);
    attest.appendChild(span);

    const actions = document.createElement('div');
    actions.className = 'modal-actions';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn btn-ghost';
    cancelBtn.id = 'consent-cancel';
    cancelBtn.textContent = 'Cancel';

    const confirmBtn = document.createElement('button');
    confirmBtn.className = 'btn btn-primary';
    confirmBtn.id = 'consent-confirm';
    confirmBtn.textContent = 'Patient consented — start recording';
    // Disabled until the attestation box is checked: the provider cannot
    // confirm consent they haven't affirmed.
    confirmBtn.disabled = true;

    box.addEventListener('change', () => { confirmBtn.disabled = !box.checked; });
    confirmBtn.addEventListener('click', () => { if (box.checked) settle(true); });
    cancelBtn.addEventListener('click', () => settle(false));

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    card.appendChild(heading);
    card.appendChild(body);
    card.appendChild(attest);
    card.appendChild(actions);

    modal.open();
    box.focus?.();
  });
}
