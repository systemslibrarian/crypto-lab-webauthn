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

// =====================================================================
// Production WebAuthn features this teaching demo does NOT (and should not)
// pretend to implement. Honest boundary — keeps the learner from confusing
// "I understand the signature seals the origin" with "I have implemented a
// production WebAuthn relying party".
// =====================================================================
export interface ProductionGap {
  title: string;
  what: string;
  why: string;
  doRealLibraries: string;
}

export const PRODUCTION_GAPS: ProductionGap[] = [
  {
    title: 'Discoverable credentials (resident keys) and BE/BS flags',
    what:
      'Production WebAuthn supports username-less login. The authenticator looks up its credentials for the RP without the server naming them, and reports two flags in authData — Backup Eligibility and Backup State — that tell the RP whether the credential is a syncable passkey (iCloud Keychain, Google Password Manager) or a single-device key.',
    why:
      'The simulator below adds a discoverable-credential lookup (Path B), but BE/BS flags require the real WebAuthn authData binary format, not the JSON shorthand this page uses.',
    doRealLibraries:
      'SimpleWebAuthn, py_webauthn, webauthn4j all decode BE/BS for you.',
  },
  {
    title: 'Conditional UI / autofill (navigator.credentials.get mediation)',
    what:
      'Modern browsers can surface passkeys directly inside the username field of a normal login form using mediation: \'conditional\'. No "Sign in with passkey" button needed.',
    why:
      'This is a browser API behavior — it cannot be simulated from JavaScript pretending to be an authenticator. The live-demo section at the bottom of the page uses the real API.',
    doRealLibraries:
      'A single PublicKeyCredentialRequestOptions object with mediation: \'conditional\' on the get() call.',
  },
  {
    title: 'CBOR / COSE encoding and hardware attestation',
    what:
      'Real authData is a packed byte structure; the public key inside it is COSE-encoded, not JWK. Registration optionally includes an attestation statement (formats: packed, fido-u2f, tpm, android-key, apple, none) that proves the model of the authenticator.',
    why:
      'This page deliberately uses JSON for the security-relevant fields so a learner can read them. Switching to CBOR/COSE/attestation would obscure the lesson without changing the security property — that is the original prompt\'s explicit scope boundary.',
    doRealLibraries:
      'cbor-x for CBOR; fido-mds3 / fido-conformance-tools for attestation root trust.',
  },
  {
    title: 'AAGUID and authenticator model identification',
    what:
      'Each authenticator family ships with a 128-bit Authenticator Attestation GUID — for example, distinguishing a YubiKey 5 NFC from Windows Hello. RPs that enforce hardware policies (e.g., FIDO-certified only) gate on AAGUID.',
    why:
      'AAGUID lives inside the attestation statement, which lives inside the CBOR-encoded attestationObject. Requires the same parsing this simulator skips.',
    doRealLibraries:
      'The FIDO Metadata Service (MDS3) maps AAGUIDs → vendor / model / certification level.',
  },
  {
    title: 'User Presence (UP) and User Verification (UV) flags',
    what:
      'The authData flags byte records whether the user actually touched the authenticator (UP) and whether biometric or PIN verification happened (UV). RPs that want multi-factor must require UV — without it, a credential alone is just possession.',
    why:
      'The simulator below now models these (Path B): you can toggle "Require user verification" and watch the verifier reject an assertion that lacks UV. The real flags byte also carries AT and ED bits this model omits.',
    doRealLibraries:
      'Every server library checks UP/UV. Production policy is almost always require: UV.',
  },
  {
    title: 'Hybrid transport (caBLE) — cross-device passkey login',
    what:
      'A user on a desktop without a local passkey can present a QR code, scan it with their phone, and complete authentication over an authenticated Bluetooth/internet channel. This is how "Sign in on this Mac using my iPhone" works.',
    why:
      'caBLE is implemented by the operating system and browser — there is nothing for a relying party to do beyond requesting any allowed credential. It is a UX feature you observe, not a verifier behavior.',
    doRealLibraries:
      'Free if you use the real browser API (Path C below). The simulator cannot reproduce it because Bluetooth and OS UI are out of scope.',
  },
];

export const SCRIPTURE_TEXT =
  '“So whether you eat or drink or whatever you do, do it all for the glory of God.”';
export const SCRIPTURE_CITATION = '1 Corinthians 10:31';
