// live.test.ts — tests for the REAL-WebAuthn path (src/live.ts).
//
// The point of these is falsifiability. The live panel prints a "Verified"
// badge; these assert that the badge is the AND of checks that each genuinely
// depend on the bytes, by mutating one field at a time and requiring the
// corresponding check — and only that check — to flip to FAIL.
//
// Test vectors are built here rather than captured from a device so the
// assertions are reproducible without an authenticator attached.

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  getLiveAssertion,
  type LiveRegistration,
  _checkClientData as checkClientData,
  _parseAuthData as parseAuthData,
  _decodeCbor as decodeCbor,
  _derToRaw as derToRaw,
  _coseToJwk as coseToJwk,
  _b64urlEncode as b64urlEncode,
  _bytesEqual as bytesEqual,
} from '../src/live';

const ORIGIN = 'https://example.com';
const RP_ID = 'example.com';
const CHALLENGE = new Uint8Array(32).map((_, i) => i);
const CHALLENGE_B64URL = b64urlEncode(CHALLENGE);

function clientData(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    type: 'webauthn.get',
    challenge: CHALLENGE_B64URL,
    origin: ORIGIN,
    crossOrigin: false,
    ...over,
  });
}

function pass(checks: { label: string; pass: boolean }[], label: string): boolean {
  const c = checks.find((x) => x.label === label);
  if (!c) throw new Error(`no check labelled ${label}`);
  return c.pass;
}

describe('live clientDataJSON checks', () => {
  it('accepts a well-formed assertion clientDataJSON', () => {
    const checks = checkClientData(clientData(), 'webauthn.get', CHALLENGE_B64URL, ORIGIN);
    expect(checks.every((c) => c.pass)).toBe(true);
  });

  it('rejects a replayed challenge, and ONLY the challenge check fails', () => {
    const stale = b64urlEncode(new Uint8Array(32).fill(9));
    const checks = checkClientData(
      clientData({ challenge: stale }),
      'webauthn.get',
      CHALLENGE_B64URL,
      ORIGIN,
    );
    expect(pass(checks, 'Challenge match')).toBe(false);
    expect(pass(checks, 'Origin match')).toBe(true);
    expect(pass(checks, 'Ceremony type')).toBe(true);
  });

  it('rejects a phishing origin, and ONLY the origin check fails', () => {
    const checks = checkClientData(
      clientData({ origin: 'https://examp1e-login.com' }),
      'webauthn.get',
      CHALLENGE_B64URL,
      ORIGIN,
    );
    expect(pass(checks, 'Origin match')).toBe(false);
    expect(pass(checks, 'Challenge match')).toBe(true);
  });

  it('rejects a registration response replayed as a login', () => {
    const checks = checkClientData(
      clientData({ type: 'webauthn.create' }),
      'webauthn.get',
      CHALLENGE_B64URL,
      ORIGIN,
    );
    expect(pass(checks, 'Ceremony type')).toBe(false);
  });

  it('rejects unparseable clientDataJSON rather than passing it', () => {
    const checks = checkClientData('{not json', 'webauthn.get', CHALLENGE_B64URL, ORIGIN);
    expect(checks.every((c) => c.pass)).toBe(false);
  });
});

// ---------------------------------------------------------------------
// authData parsing, against the byte layout in W3C WebAuthn 6.1:
//   rpIdHash(32) | flags(1) | signCount(4 BE) | [aaguid(16) | credIdLen(2 BE) | credId | COSE key]
// ---------------------------------------------------------------------
async function sha256(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', b));
}

function buildAuthData(opts: {
  rpIdHash: Uint8Array;
  flags: number;
  signCount: number;
  attested?: { aaguid: Uint8Array; credId: Uint8Array; coseKey: Uint8Array };
}): Uint8Array {
  const head = new Uint8Array(37);
  head.set(opts.rpIdHash, 0);
  head[32] = opts.flags;
  new DataView(head.buffer).setUint32(33, opts.signCount);
  if (!opts.attested) return head;
  const { aaguid, credId, coseKey } = opts.attested;
  const out = new Uint8Array(37 + 16 + 2 + credId.length + coseKey.length);
  out.set(head, 0);
  out.set(aaguid, 37);
  new DataView(out.buffer).setUint16(53, credId.length);
  out.set(credId, 55);
  out.set(coseKey, 55 + credId.length);
  return out;
}

describe('parseAuthData', () => {
  it('reads the rpIdHash, each flag bit, and the big-endian signCount', async () => {
    const rpIdHash = await sha256(new TextEncoder().encode(RP_ID));
    // UP(0x01) | UV(0x04) | BE(0x08) | BS(0x10) — AT and ED clear.
    const ad = buildAuthData({ rpIdHash, flags: 0x01 | 0x04 | 0x08 | 0x10, signCount: 0x01020304 });
    const p = parseAuthData(ad);
    expect(bytesEqual(p.rpIdHash, rpIdHash)).toBe(true);
    expect(p.flags).toEqual({ up: true, uv: true, be: true, bs: true, at: false, ed: false });
    expect(p.signCount).toBe(0x01020304);
    expect(p.aaguid).toBeUndefined();
  });

  it('reads the AAGUID out of attested credential data, not an attestation statement', async () => {
    const rpIdHash = await sha256(new TextEncoder().encode(RP_ID));
    const aaguid = new Uint8Array(16).map((_, i) => i + 1);
    const credId = new Uint8Array([9, 8, 7, 6]);
    // CBOR map {} — enough to prove the offset arithmetic lands on the key.
    const coseKey = new Uint8Array([0xa0]);
    const ad = buildAuthData({
      rpIdHash,
      flags: 0x01 | 0x40, // UP | AT
      signCount: 0,
      attested: { aaguid, credId, coseKey },
    });
    const p = parseAuthData(ad);
    expect(p.flags.at).toBe(true);
    expect(p.aaguid && bytesEqual(p.aaguid, aaguid)).toBe(true);
    expect(p.credentialId && bytesEqual(p.credentialId, credId)).toBe(true);
  });
});

describe('DER -> raw r||s', () => {
  it('left-pads short integers to 32 bytes', () => {
    // SEQUENCE { INTEGER 0x01, INTEGER 0x02 }
    const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
    const raw = derToRaw(der, 32);
    expect(raw.length).toBe(64);
    expect(raw[31]).toBe(1);
    expect(raw[63]).toBe(2);
    expect(raw.slice(0, 31).every((b) => b === 0)).toBe(true);
  });

  it('strips the 0x00 sign byte DER adds to a high-bit integer', () => {
    const r = new Uint8Array(33);
    r[0] = 0x00;
    r.fill(0xff, 1);
    const der = new Uint8Array([0x30, 0x81, 0x00, 0x02, 33, ...r, 0x02, 0x01, 0x05]);
    der[2] = der.length - 3;
    const raw = derToRaw(der, 32);
    expect(raw.slice(0, 32).every((b) => b === 0xff)).toBe(true);
    expect(raw[63]).toBe(5);
  });
});

describe('COSE -> JWK', () => {
  it('converts an EC2 / P-256 key', () => {
    const cose = new Map<number, unknown>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, new Uint8Array(32).fill(1)],
      [-3, new Uint8Array(32).fill(2)],
    ]);
    const jwk = coseToJwk(cose);
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
  });

  it('refuses a non-EC2 key rather than emitting a bogus JWK', () => {
    const cose = new Map<number, unknown>([[1, 3]]); // kty: RSA
    expect(() => coseToJwk(cose)).toThrow();
  });
});

describe('CBOR decoder', () => {
  it('decodes the map/byte-string shape of an attestationObject', () => {
    // {"fmt": "none", "authData": h'AABB'}
    const bytes = new Uint8Array([
      0xa2,
      0x63, 0x66, 0x6d, 0x74, // "fmt"
      0x64, 0x6e, 0x6f, 0x6e, 0x65, // "none"
      0x68, 0x61, 0x75, 0x74, 0x68, 0x44, 0x61, 0x74, 0x61, // "authData"
      0x42, 0xaa, 0xbb, // h'AABB'
    ]);
    const m = decodeCbor(bytes).value as Map<string, unknown>;
    expect(m.get('fmt')).toBe('none');
    expect(bytesEqual(m.get('authData') as Uint8Array, new Uint8Array([0xaa, 0xbb]))).toBe(true);
  });

  it('decodes CBOR negative integers (COSE alg -7 / label -2)', () => {
    expect(decodeCbor(new Uint8Array([0x26])).value).toBe(-7);
  });
});


// Exercise the actual live assertion orchestrator with signed wire bytes and
// a controlled credential provider. No hardware or browser ceremony is claimed.
afterEach(() => vi.unstubAllGlobals());

function rawToDer(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const value = bytes.slice(start);
    const positive = value[0] & 0x80 ? new Uint8Array([0, ...value]) : value;
    return new Uint8Array([2, positive.length, ...positive]);
  };
  const r = integer(raw.slice(0, 32)), s = integer(raw.slice(32));
  return new Uint8Array([0x30, r.length + s.length, ...r, ...s]);
}

type LiveFault = 'challenge' | 'origin' | 'type' | 'rpHash' | 'credentialId' | 'signature' | 'up' | 'json' | 'truncated' | 'cancelled' | 'null';
async function liveFixture(last = 1, initial: { count?: number; fault?: LiveFault } = {}) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const rpIdHash = await sha256(new TextEncoder().encode(RP_ID));
  const id = new Uint8Array([9, 8, 7, 6]);
  const registered: LiveRegistration = {
    credentialId: b64urlEncode(id), credentialIdRaw: id.buffer,
    aaguid: '00000000-0000-0000-0000-000000000000', aaguidIsZero: true,
    transports: [], publicKeyJwk: await crypto.subtle.exportKey('jwk', kp.publicKey),
    publicKeyImported: kp.publicKey,
    flags: { up: true, uv: false, be: false, bs: false, at: true, ed: false },
    signCount: last, lastSignCount: last, clientDataJSON: '{}', authDataLen: 37,
    rpId: RP_ID, rpIdHash, checks: [],
  };
  let current = initial;
  vi.stubGlobal('window', { location: { origin: ORIGIN }, PublicKeyCredential: class {} });
  vi.stubGlobal('navigator', { credentials: { get: async (options: CredentialRequestOptions) => {
    if (current.fault === 'cancelled') throw new Error('provider cancelled');
    if (current.fault === 'null') return null;
    const fault = current.fault;
    const requested = new Uint8Array(options.publicKey!.challenge as ArrayBuffer);
    const cdata = new TextEncoder().encode(fault === 'json' ? '{not json' : clientData({
      challenge: b64urlEncode(fault === 'challenge' ? new Uint8Array([0]) : requested),
      origin: fault === 'origin' ? 'https://wrong.example' : ORIGIN,
      type: fault === 'type' ? 'webauthn.create' : 'webauthn.get',
    }));
    const authData = buildAuthData({
      rpIdHash: fault === 'rpHash' ? new Uint8Array(32) : rpIdHash,
      flags: fault === 'up' ? 0 : 1, signCount: current.count ?? last + 1,
    });
    const hash = await sha256(cdata);
    const signed = new Uint8Array([...authData, ...hash]);
    const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, signed));
    if (fault === 'signature') sig[0] ^= 1;
    return {
      rawId: (fault === 'credentialId' ? new Uint8Array([1, 2, 3]) : id).buffer,
      response: { clientDataJSON: cdata.buffer,
        authenticatorData: (fault === 'truncated' ? authData.slice(0, 2) : authData).buffer,
        signature: rawToDer(sig).buffer },
    };
  } } });
  return { registered, set: (value: typeof initial) => { current = value; } };
}

describe('live assertion acceptance and counter state', () => {
  it('accepted signed wire assertion advances the persisted counter', async () => {
    const { registered } = await liveFixture();
    const r = await getLiveAssertion(registered, RP_ID);
    expect(r.verified).toBe(true);
    expect(r.checks.every(c => c.pass)).toBe(true);
    expect(registered.lastSignCount).toBe(2);
  });

  it.each([
    ['challenge', 'Challenge match'], ['origin', 'Origin match'], ['type', 'Ceremony type'],
    ['rpHash', 'RP ID hash'], ['credentialId', 'Credential ID known'],
    ['signature', 'Signature valid'], ['up', 'User present (UP)'], ['json', 'Client data parsed'],
  ] as const)('rejected %s assertion cannot advance an otherwise-increasing counter', async (fault, label) => {
    const { registered } = await liveFixture(1, { fault, count: 100 });
    const r = await getLiveAssertion(registered, RP_ID);
    expect(r.verified).toBe(false);
    expect(r.checks.some(c => !c.pass)).toBe(true);
    if (fault !== 'json') expect(pass(r.checks, label)).toBe(false);
    expect(pass(r.checks, 'Counter increasing')).toBe(true);
    if (fault !== 'signature') expect(pass(r.checks, 'Signature valid')).toBe(true);
    expect(registered.lastSignCount).toBe(1);
  });

  it('a rejected high counter cannot poison a later valid lower assertion', async () => {
    const fixture = await liveFixture(1, { fault: 'origin', count: 100 });
    expect((await getLiveAssertion(fixture.registered, RP_ID)).verified).toBe(false);
    fixture.set({ count: 2 });
    expect((await getLiveAssertion(fixture.registered, RP_ID)).verified).toBe(true);
    expect(fixture.registered.lastSignCount).toBe(2);
  });

  it.each([0, 1, 3])('equal/decreasing counter %s does not change accepted state', async count => {
    const { registered } = await liveFixture(3, { count });
    const r = await getLiveAssertion(registered, RP_ID);
    expect(r.verified).toBe(false);
    expect(pass(r.checks, 'Counter increasing')).toBe(false);
    expect(registered.lastSignCount).toBe(3);
  });

  it('all-zero unsupported counters remain accepted without claiming clone detection', async () => {
    const { registered } = await liveFixture(0, { count: 0 });
    const r = await getLiveAssertion(registered, RP_ID);
    expect(r.verified).toBe(true);
    expect(registered.lastSignCount).toBe(0);
    expect(r.checks.find(c => c.label === 'Counter increasing')?.detail).toContain('cannot run');
  });

  it.each(['truncated', 'cancelled', 'null'] as const)('unreadable/unfinished %s response leaves state unchanged', async fault => {
    const { registered } = await liveFixture(1, { fault, count: 100 });
    await expect(getLiveAssertion(registered, RP_ID)).rejects.toThrow();
    expect(registered.lastSignCount).toBe(1);
  });
});
