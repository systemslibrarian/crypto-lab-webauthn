// engine.test.ts — fast, isolated unit tests over the security-critical WebAuthn
// engine. These assert the pure ceremony logic that the browser e2e only touched
// indirectly: the five verifier checks, the UP/UV policy gates, the four attacks,
// and — crucially — that the signCount (counter) check is INDEPENDENT of the
// signature check. They use real ECDSA P-256 via Web Crypto plus frozen KATs.

import { describe, it, expect } from 'vitest';
import {
  Authenticator,
  RelyingParty,
  randomChallenge,
  AUTH_FLAG_UP,
  AUTH_FLAG_UV,
  shortB64,
  type Assertion,
  type VerifyResult,
} from '../src/engine';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';
const ORIGIN_PHISH = 'https://examp1e-login.com';

// -------------------------------------------------------------------------
// Small helpers shared by the scenarios.
// -------------------------------------------------------------------------
async function freshCeremony() {
  const auth = new Authenticator();
  const rp = new RelyingParty();
  const cred = await auth.makeCredential(RP_ID);
  rp.register(cred);
  return { auth, rp, cred };
}

async function authenticate(
  auth: Authenticator,
  credentialId: string,
  challenge: string,
  origin = ORIGIN,
  rpId = RP_ID,
  options?: { userPresent?: boolean; userVerified?: boolean },
): Promise<Assertion> {
  const a = await auth.getAssertion(credentialId, challenge, origin, rpId, options);
  if ('error' in a) throw new Error(`unexpected authenticator error: ${a.error}`);
  return a;
}

function check(result: VerifyResult, label: string) {
  const c = result.checks.find((x) => x.label === label);
  if (!c) throw new Error(`no check labelled "${label}" — have: ${result.checks.map((x) => x.label).join(', ')}`);
  return c;
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(u: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s);
}

// =========================================================================
// Known-answer tests: lock the primitives the whole design rests on.
// =========================================================================
describe('known-answer tests (real crypto primitives)', () => {
  // SHA-256 of the RP id is what binds authData to the relying party. This is
  // an independent KAT vector (echo -n example.com | sha256sum).
  it('SHA-256("example.com") matches the reference digest', async () => {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('example.com'));
    const hex = Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
    expect(hex).toBe('a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947');
  });

  // Frozen P-256 verification vector: a fixed public key must verify a fixed
  // signature over a fixed message. Guards against Web Crypto param drift.
  it('verifies a frozen ECDSA P-256 signature vector', async () => {
    const pub: JsonWebKey = {
      kty: 'EC',
      crv: 'P-256',
      x: 'ChLfhTcpnlxpv9NTlTnElIvtKcd-0IEuYsu93ypdDOM',
      y: 'y1-35PSsyF4wsVy5aUN5Vz3WNoSGS9xZkfDwsmhmn1c',
      ext: true,
    };
    const sigB64 =
      'M5sZT2ApcZQ0ICYu6rUcrR+wKshevynJKFJEw/mcrmv6V9CVwBdgQqtNIHIBhJLFMoC0NZHXPWm6A3ht2xDLKA==';
    const msg = new TextEncoder().encode('webauthn-kat-message-v1');
    const key = await crypto.subtle.importKey('jwk', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64ToBytes(sigB64),
      msg,
    );
    expect(ok).toBe(true);

    // A single-bit flip of that frozen signature must NOT verify.
    const bad = b64ToBytes(sigB64);
    bad[0] ^= 0x01;
    const okBad = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bad, msg);
    expect(okBad).toBe(false);
  });

  it('randomChallenge() returns 32 random bytes, base64, non-repeating', () => {
    const c1 = randomChallenge();
    const c2 = randomChallenge();
    expect(c1).not.toBe(c2);
    expect(b64ToBytes(c1).length).toBe(32);
  });
});

// =========================================================================
// The happy path: register → authenticate → verify passes every check.
// =========================================================================
describe('happy path ceremony', () => {
  it('a legitimate assertion passes all five core checks', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const a = await authenticate(auth, cred.credentialId, challenge);
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(true);
    expect(result.checks).toHaveLength(5);
    for (const c of result.checks) expect(c.pass).toBe(true);
    expect(result.summary).toMatch(/Authenticated/);
  });

  it('the private key never leaves the authenticator (server stores only a public JWK)', async () => {
    const { cred } = await freshCeremony();
    expect(cred.publicKeyJwk.kty).toBe('EC');
    expect(cred.publicKeyJwk.crv).toBe('P-256');
    // The stored credential must NOT carry the private scalar `d`.
    expect(cred.publicKeyJwk.d).toBeUndefined();
    expect((cred.publicKeyJwk.key_ops ?? [])).not.toContain('sign');
  });

  it('the monotonic counter increases on each assertion', async () => {
    const { auth, cred } = await freshCeremony();
    const a1 = await authenticate(auth, cred.credentialId, randomChallenge());
    const a2 = await authenticate(auth, cred.credentialId, randomChallenge());
    expect(a2.signCount).toBeGreaterThan(a1.signCount);
  });
});

// =========================================================================
// The four attacks — each must fail on exactly the right check.
// =========================================================================
describe('attacks bounce off the design', () => {
  it('PHISHING: a wrong origin fails the Origin check', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    // The authenticator signs the phishing origin the browser actually saw.
    const a = await authenticate(auth, cred.credentialId, challenge, ORIGIN_PHISH);
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'Origin match').pass).toBe(false);
    // The signature itself is valid — the origin was genuinely signed.
    expect(check(result, 'Signature valid').pass).toBe(true);
  });

  it('REPLAY: replaying an old assertion against a fresh challenge fails Challenge match', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge1 = randomChallenge();
    const a = await authenticate(auth, cred.credentialId, challenge1);
    // First use succeeds.
    const first = await rp.verifyAssertion(a, {
      expectedChallenge: challenge1,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(first.ok).toBe(true);
    // Server issues a NEW challenge; the attacker replays the same assertion.
    const challenge2 = randomChallenge();
    const replay = await rp.verifyAssertion(a, {
      expectedChallenge: challenge2,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(replay.ok).toBe(false);
    expect(check(replay, 'Challenge match').pass).toBe(false);
  });

  it('WRONG RP: the authenticator refuses to sign for an rpId it is not bound to', async () => {
    const { auth, cred } = await freshCeremony();
    const res = await auth.getAssertion(cred.credentialId, randomChallenge(), ORIGIN, 'evil.com');
    expect('error' in res).toBe(true);
    if ('error' in res) expect(res.error).toMatch(/refuses|bound/i);
  });

  it('CLONE / COUNTER: a lowered signCount fails the Counter check while the SIGNATURE still verifies', async () => {
    const { auth, rp, cred } = await freshCeremony();
    // Advance the server's last-seen counter with a legit assertion.
    const c1 = randomChallenge();
    const legit = await authenticate(auth, cred.credentialId, c1);
    await rp.verifyAssertion(legit, { expectedChallenge: c1, expectedOrigin: ORIGIN, expectedRpId: RP_ID });

    // A cloned authenticator lags behind: it presents a validly-signed assertion
    // but with a stale (lower) counter. We model the clone the way the demo does:
    // lower ONLY the a.signCount field the verifier reads, leaving authData (the
    // signed bytes) intact — so the signature still verifies.
    const c2 = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, c2);
    const cloned: Assertion = { ...good, signCount: 0 };

    const result = await rp.verifyAssertion(cloned, {
      expectedChallenge: c2,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    // THE POINT: counter fails, signature passes — the two checks are independent.
    expect(check(result, 'Counter increasing').pass).toBe(false);
    expect(check(result, 'Signature valid').pass).toBe(true);
  });
});

// =========================================================================
// Counter-check independence, stated as its own dedicated property.
// This is the subtle bit the original gaps called out: because authData is
// signed, mutating the SIGNED counter breaks the signature, but the verifier
// also reads a separate a.signCount field, and THAT is what the counter check
// consumes. The two failures must be distinguishable.
// =========================================================================
describe('counter check is independent of the signature check', () => {
  it('mutating the SIGNED authData counter breaks the SIGNATURE (not just the counter)', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, challenge);

    // Bump the counter INSIDE authData (the signed bytes). This is the "tamper"
    // path in the UI: the signature must reject because the recomputed bytes
    // differ from what was signed.
    const parts = good.authData.split('|');
    const tampered: Assertion = {
      ...good,
      authData: `${parts[0]}|${parts[1]}|999`,
      signCount: 999,
    };
    const result = await rp.verifyAssertion(tampered, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'Signature valid').pass).toBe(false);
  });

  it('lowering ONLY the unsigned a.signCount field trips the counter but leaves the signature valid', async () => {
    const { auth, rp, cred } = await freshCeremony();
    // Prime the server counter.
    const c1 = randomChallenge();
    const a1 = await authenticate(auth, cred.credentialId, c1);
    await rp.verifyAssertion(a1, { expectedChallenge: c1, expectedOrigin: ORIGIN, expectedRpId: RP_ID });

    const c2 = randomChallenge();
    const a2 = await authenticate(auth, cred.credentialId, c2);
    const stale: Assertion = { ...a2, signCount: 1 }; // <= last seen
    const result = await rp.verifyAssertion(stale, {
      expectedChallenge: c2,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(check(result, 'Signature valid').pass).toBe(true);
    expect(check(result, 'Counter increasing').pass).toBe(false);
  });

  it('an equal (non-increasing) counter is rejected — strict monotonicity', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const c1 = randomChallenge();
    const a1 = await authenticate(auth, cred.credentialId, c1);
    const r1 = await rp.verifyAssertion(a1, { expectedChallenge: c1, expectedOrigin: ORIGIN, expectedRpId: RP_ID });
    expect(r1.ok).toBe(true);

    const c2 = randomChallenge();
    const a2 = await authenticate(auth, cred.credentialId, c2);
    const equal: Assertion = { ...a2, signCount: a1.signCount }; // equal, not >
    const r2 = await rp.verifyAssertion(equal, { expectedChallenge: c2, expectedOrigin: ORIGIN, expectedRpId: RP_ID });
    expect(check(r2, 'Counter increasing').pass).toBe(false);
  });
});

// =========================================================================
// Signature forgery is genuinely caught (not a checksum).
// =========================================================================
describe('signature verification rejects forgery', () => {
  it('flipping one bit of the signature fails the Signature check', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, challenge);
    const bytes = b64ToBytes(good.signatureB64);
    bytes[0] ^= 0x01;
    const forged: Assertion = { ...good, signatureB64: bytesToB64(bytes) };
    const result = await rp.verifyAssertion(forged, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'Signature valid').pass).toBe(false);
  });

  it('forging the origin in clientDataJSON fails BOTH origin and signature checks', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, challenge);
    const client = JSON.parse(good.clientDataJSON) as { type: string; challenge: string; origin: string };
    client.origin = ORIGIN_PHISH;
    const forged: Assertion = { ...good, clientDataJSON: JSON.stringify(client) };
    const result = await rp.verifyAssertion(forged, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'Origin match').pass).toBe(false);
    expect(check(result, 'Signature valid').pass).toBe(false);
  });

  it('a substituted public key (attacker key) fails signature verification', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, challenge);
    // Attacker swaps the stored public key for their own.
    const attacker = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const attackerJwk = await crypto.subtle.exportKey('jwk', attacker.publicKey);
    rp.credentials.set(cred.credentialId, { ...cred, publicKeyJwk: attackerJwk });
    const result = await rp.verifyAssertion(good, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(check(result, 'Signature valid').pass).toBe(false);
  });

  it('an unknown credential id is rejected outright', async () => {
    const { rp } = await freshCeremony();
    const bogus: Assertion = {
      credentialId: 'does-not-exist',
      signatureB64: '',
      authData: 'x|5|1',
      clientDataJSON: JSON.stringify({ type: 'webauthn.get', challenge: 'c', origin: ORIGIN }),
      signCount: 1,
      flags: AUTH_FLAG_UP | AUTH_FLAG_UV,
    };
    const result = await rp.verifyAssertion(bogus, {
      expectedChallenge: 'c',
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(false);
    expect(result.summary).toMatch(/unknown credential/i);
  });
});

// =========================================================================
// wrong rpId hash is caught by the verifier even when the authenticator signed.
// =========================================================================
describe('rpId hash binding', () => {
  it('verifying with a different expectedRpId fails the RP ID hash check', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const good = await authenticate(auth, cred.credentialId, challenge);
    const result = await rp.verifyAssertion(good, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: 'other-rp.example', // server thinks it is a different RP
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'RP ID hash').pass).toBe(false);
  });
});

// =========================================================================
// UP / UV policy gates.
// =========================================================================
describe('User Present / User Verified policy', () => {
  it('default assertion sets both UP and UV flags', async () => {
    const { auth, cred } = await freshCeremony();
    const a = await authenticate(auth, cred.credentialId, randomChallenge());
    expect(a.flags & AUTH_FLAG_UP).toBe(AUTH_FLAG_UP);
    expect(a.flags & AUTH_FLAG_UV).toBe(AUTH_FLAG_UV);
  });

  it('requireUV fails when the authenticator did not verify the user', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const a = await authenticate(auth, cred.credentialId, challenge, ORIGIN, RP_ID, { userVerified: false });
    expect(a.flags & AUTH_FLAG_UV).toBe(0);
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      requireUV: true,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'User verified (UV)').pass).toBe(false);
    // The signature over the (UV=0) flags is still valid — only policy fails.
    expect(check(result, 'Signature valid').pass).toBe(true);
  });

  it('requireUP fails when the user was not present', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const a = await authenticate(auth, cred.credentialId, challenge, ORIGIN, RP_ID, { userPresent: false });
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      requireUP: true,
    });
    expect(result.ok).toBe(false);
    expect(check(result, 'User present (UP)').pass).toBe(false);
  });

  it('requireUV passes for a fully-verified assertion, adding a 6th check', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const a = await authenticate(auth, cred.credentialId, challenge);
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
      requireUV: true,
    });
    expect(result.ok).toBe(true);
    expect(result.checks).toHaveLength(6);
    expect(check(result, 'User verified (UV)').pass).toBe(true);
  });
});

// =========================================================================
// Discoverable credentials (resident-key style) still enforce every check.
// =========================================================================
describe('discoverable credential lookup', () => {
  it('getAssertionByRpId picks a bound credential and verifies', async () => {
    const { auth, rp, cred } = await freshCeremony();
    const challenge = randomChallenge();
    const a = await auth.getAssertionByRpId(RP_ID, challenge, ORIGIN);
    if ('error' in a) throw new Error(a.error);
    expect(a.credentialId).toBe(cred.credentialId);
    const result = await rp.verifyAssertion(a, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN,
      expectedRpId: RP_ID,
    });
    expect(result.ok).toBe(true);
  });

  it('getAssertionByRpId errors when no credential is bound to the rpId', async () => {
    const { auth } = await freshCeremony();
    const res = await auth.getAssertionByRpId('nobody.example', randomChallenge(), ORIGIN);
    expect('error' in res).toBe(true);
  });
});

describe('shortB64 helper', () => {
  it('truncates long strings and leaves short ones intact', () => {
    expect(shortB64('abc', 16)).toBe('abc');
    expect(shortB64('0123456789abcdefXYZ', 16)).toBe('0123456789abcdef…');
  });
});
