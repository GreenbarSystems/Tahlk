// Auto-chain sequencer for the "stop recording → signed note" loop.
//
// After audio is saved, transcription and note generation used to be two
// separate manual clicks with two waits. This runs them back-to-back so the
// clinician's mental model ("stop talking → show me the note") holds. The two
// phases share ONE status banner (driven by transcribeNow/generateNow), so the
// UI reads as a single continuous operation rather than two disconnected ones.
//
// Kept as a tiny pure sequencer — no DOM, no imports — so the chaining rule
// (generation only runs when transcription succeeded) is unit-testable in
// isolation from the section wiring. The section functions own their own
// error surfacing (a failed transcription toasts + clears the banner); this
// only decides whether to proceed.

export async function runScribeChain({ transcribeNow, generateNow }) {
  const transcribed = await transcribeNow({ chain: true });
  if (!transcribed) return false;
  await generateNow({ chain: true });
  return true;
}
