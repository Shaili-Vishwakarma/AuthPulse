/* AuthPulse – How It Works page */
import { icon, refreshIcons } from './core.js';

export function renderHowItWorks(root) {
  const steps = [
    { title: '1. Canonicalize the Payload', body: 'The sender serializes the JSON payload with sorted keys and compact separators (no spaces). This ensures both sides compute the same signing string.' },
    { title: '2. Build the Signing String', body: 'Concatenate timestamp, nonce, and canonical payload as "{timestamp}.{nonce}.{canonical_json}". All three components are included in what gets signed.' },
    { title: '3. Compute HMAC-SHA256', body: 'The signing string is passed through HMAC-SHA256 using a shared secret key. The output hex digest is the authentication tag.' },
    { title: '4. Attach Metadata', body: 'The sender transmits the payload, timestamp, nonce, and tag to the receiver. The secret key never leaves the sender.' },
    { title: '5. Recompute the HMAC', body: 'The receiver reconstructs the same signing string from the received payload, timestamp, and nonce, then computes its own HMAC tag.' },
    { title: '6. Compare Tags (Tamper Detection)', body: 'The receiver compares the recomputed tag with the received tag using hmac.compare_digest (constant-time comparison). A mismatch means the payload was altered.' },
    { title: '7. Check Timestamp Window', body: 'The receiver verifies the timestamp is within a 60-second window of the current time. This prevents old messages from being reused.' },
    { title: '8. Check Nonce Uniqueness (Replay Prevention)', body: 'The receiver stores each nonce in a database with a UNIQUE constraint. If the nonce already exists, the request is a replay and is rejected.' },
    { title: '9. Accept or Reject', body: 'Only if all three checks pass (HMAC, timestamp, nonce) is the message accepted. The result and per-check trace are stored and returned.' },
  ];
  root.innerHTML = `<div class="card">
    <div class="card-title">The 9-Step Message Authentication Protocol</div>
    <div class="step-list">
      ${steps.map(s => `<div class="step">
        <div class="step-number">${s.title.split('.')[0]}</div>
        <div class="step-content">
          <h3>${s.title.split('. ').slice(1).join('. ')}</h3>
          <p>${s.body}</p>
        </div>
      </div>`).join('')}
    </div>
    <div class="callout">
      <strong>Important limitations:</strong>
      HMAC alone does not stop replay attacks — an attacker who captures a valid message can resend it.
      That is why we combine HMAC with a nonce uniqueness check and a timestamp window.
      HMAC also does not encrypt the payload — the message content is sent in the clear.
      For confidentiality, use TLS in transit or encrypt the payload separately.
    </div>
  </div>`;
  refreshIcons();
}
