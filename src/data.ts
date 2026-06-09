// data.ts — copy/content for the WebAuthn / passkeys demo.
// Only plain content arrays here — no crypto, no DOM.

export interface CeremonyStep {
  phase: 'Registration' | 'Authentication';
  ordinal: number;
  actor: string;
  action: string;
}

export const CEREMONY_STEPS: CeremonyStep[] = [
  {
    phase: 'Registration',
    ordinal: 1,
    actor: 'Server (Relying Party)',
    action: 'Generates a one-time random challenge and asks the browser to create a passkey for its origin.',
  },
  {
    phase: 'Registration',
    ordinal: 2,
    actor: 'Authenticator (phone / security key)',
    action: 'Creates a fresh ECDSA P-256 keypair bound to the RP ID. The private key is held inside the authenticator.',
  },
  {
    phase: 'Registration',
    ordinal: 3,
    actor: 'Authenticator → Server',
    action: 'Returns the credential ID and PUBLIC key. The server stores them — no secret is shared.',
  },
  {
    phase: 'Authentication',
    ordinal: 1,
    actor: 'Server',
    action: 'Issues a new random challenge for this login attempt.',
  },
  {
    phase: 'Authentication',
    ordinal: 2,
    actor: 'Authenticator',
    action: 'Signs (challenge ‖ origin ‖ rpIdHash ‖ signCount) with the private key. The private key never leaves.',
  },
  {
    phase: 'Authentication',
    ordinal: 3,
    actor: 'Server',
    action: 'Verifies the signature with the stored public key and checks challenge, origin, rpId hash, and counter.',
  },
];

export interface PhishingCard {
  title: string;
  body: string;
}

export const WHY_PHISHING_FAILS: PhishingCard[] = [
  {
    title: 'The origin is signed',
    body: 'The authenticator includes the origin the browser actually saw inside the bytes it signs. A look-alike domain produces a signature that does not match what the server expects, and the login is rejected.',
  },
  {
    title: 'Credentials are bound to one RP',
    body: 'A passkey for example.com only exists for example.com. The authenticator refuses to use it for evil.com — there is nothing to misdirect to a fake site.',
  },
  {
    title: 'No shared secret to steal',
    body: 'The server stores only a public key, not a password. There is no secret on the server that a phishing form could trick the user into typing, and there is nothing for an attacker to harvest.',
  },
  {
    title: 'Fresh challenges block replay',
    body: 'Each login uses a new challenge, signed once. Capturing a valid assertion does not help: replaying it against a new challenge fails the freshness check.',
  },
];

export interface ComparisonRow {
  property: string;
  password: string;
  passkey: string;
}

export const PASSWORD_VS_PASSKEY: ComparisonRow[] = [
  {
    property: 'Kind of secret',
    password: 'A shared secret the user knows and the server stores (hashed).',
    passkey: 'A private key the authenticator holds; the server only knows the matching public key.',
  },
  {
    property: 'Phishability',
    password: 'Phishable — any look-alike page can collect it.',
    passkey: 'Origin-bound — the signed origin makes look-alike sites fail verification.',
  },
  {
    property: 'Server breach impact',
    password: 'Hash database leaks fuel offline cracking.',
    passkey: 'Public keys are not secrets; a leak gives an attacker nothing to log in with.',
  },
  {
    property: 'Reuse across sites',
    password: 'Often reused — one breach compromises many sites.',
    passkey: 'One distinct keypair per site, generated automatically.',
  },
  {
    property: 'What the user does',
    password: 'Remembers and types a string.',
    passkey: 'Approves a prompt (biometric / PIN); never types a secret.',
  },
];

export interface RealWorldNote {
  title: string;
  body: string;
}

export const REAL_WORLD: RealWorldNote[] = [
  {
    title: 'A W3C / FIDO standard',
    body: 'WebAuthn is a W3C specification. The authenticator side speaks CTAP2 (FIDO2). Browsers expose the API as navigator.credentials.create / .get.',
  },
  {
    title: 'Passkeys across platforms',
    body: 'Apple, Google, and Microsoft each ship passkey support: iCloud Keychain, Google Password Manager, and Windows Hello respectively. The credential format is interoperable.',
  },
  {
    title: 'Syncable vs device-bound',
    body: 'Consumer passkeys are typically synced across a user’s devices through their platform account. Hardware security keys (YubiKey, Titan) hold device-bound credentials that cannot be exported.',
  },
  {
    title: 'What this demo simplifies',
    body: 'Real WebAuthn wraps the same security logic in CBOR-encoded authenticator data, COSE-encoded keys, and an attestation statement. This page models the security checks — the challenge, origin, RP ID, signature, and counter — without the wire format.',
  },
];

export const SCRIPTURE_TEXT =
  '“So whether you eat or drink or whatever you do, do it all for the glory of God.”';
export const SCRIPTURE_CITATION = '1 Corinthians 10:31';
