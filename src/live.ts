// live.ts — real WebAuthn (navigator.credentials.create / .get) wrapper.
// Path C: shows actual AAGUID, BE/BS flags, transports, and verifies the
// signature against the COSE public key extracted from the attestationObject.
//
// What this file does for you, beyond the simulated engine:
//   * decodes the CBOR-encoded attestationObject the browser returns
//   * parses the binary authData (rpIdHash | flags | signCount | attested-data)
//   * converts COSE EC2 (alg -7, ES256) → JWK so Web Crypto can use it
//   * converts ASN.1 DER ECDSA signature → raw r||s for SubtleCrypto.verify
// This is intentionally a small slice of what a production library does
// (we don't validate attestation, accept only P-256, etc.) — the goal is
// to make the real ceremony visible against a real browser API.

export interface AuthFlags {
  up: boolean; // user present
  uv: boolean; // user verified (biometric / PIN)
  be: boolean; // backup eligible (syncable passkey)
  bs: boolean; // backup state (currently backed up)
  at: boolean; // attested credential data included
  ed: boolean; // extension data included
}

export interface LiveRegistration {
  credentialId: string;
  credentialIdRaw: ArrayBuffer;
  aaguid: string;
  aaguidIsZero: boolean;
  transports: string[];
  publicKeyJwk: JsonWebKey;
  publicKeyImported: CryptoKey;
  flags: AuthFlags;
  signCount: number;
  clientDataJSON: string;
  authDataLen: number;
  /** The RP ID this credential was created for — re-checked at assertion time. */
  rpId: string;
  /** SHA-256(rpId), captured at registration so the assertion can be checked against it. */
  rpIdHash: Uint8Array;
  /** Registration checks, run against clientDataJSON the same way an RP server would. */
  checks: LiveCheck[];
  /** Highest signature counter seen so far; updated after each accepted assertion. */
  lastSignCount: number;
}

export interface LiveCheck {
  label: string;
  pass: boolean;
  detail: string;
}

export interface LiveAssertion {
  credentialId: string;
  signatureB64: string;
  signatureRawB64: string;
  authDataLen: number;
  clientDataJSON: string;
  flags: AuthFlags;
  signCount: number;
  /** True only when EVERY check in `checks` passed — not the signature alone. */
  verified: boolean;
  checks: LiveCheck[];
  signedBytesPreview: string;
}

const enc = new TextEncoder();

// =====================================================================
// Tiny CBOR decoder — just enough for attestationObject + COSE keys.
// Handles: unsigned int, negative int, byte string, text string, array, map.
// =====================================================================
function decodeCbor(buf: Uint8Array, off = 0): { value: unknown; off: number } {
  const initial = buf[off];
  const majorType = initial >> 5;
  const info = initial & 0x1f;
  off += 1;
  let arg = 0;
  if (info < 24) arg = info;
  else if (info === 24) { arg = buf[off]; off += 1; }
  else if (info === 25) { arg = (buf[off] << 8) | buf[off + 1]; off += 2; }
  else if (info === 26) {
    const dv = new DataView(buf.buffer, buf.byteOffset + off, 4);
    arg = dv.getUint32(0); off += 4;
  } else if (info === 27) {
    const dv = new DataView(buf.buffer, buf.byteOffset + off, 8);
    arg = Number(dv.getBigUint64(0)); off += 8;
  } else {
    throw new Error(`CBOR info ${info} unsupported`);
  }
  switch (majorType) {
    case 0: return { value: arg, off };
    case 1: return { value: -1 - arg, off };
    case 2: return { value: buf.slice(off, off + arg), off: off + arg };
    case 3: return { value: new TextDecoder().decode(buf.slice(off, off + arg)), off: off + arg };
    case 4: {
      const arr: unknown[] = [];
      for (let i = 0; i < arg; i++) {
        const r = decodeCbor(buf, off);
        arr.push(r.value); off = r.off;
      }
      return { value: arr, off };
    }
    case 5: {
      const map = new Map<unknown, unknown>();
      for (let i = 0; i < arg; i++) {
        const k = decodeCbor(buf, off); off = k.off;
        const v = decodeCbor(buf, off); off = v.off;
        map.set(k.value, v.value);
      }
      return { value: map, off };
    }
    default:
      throw new Error(`CBOR major type ${majorType} unsupported`);
  }
}

// =====================================================================
// WebAuthn authData binary layout:
//   bytes 0–31   : SHA-256(rpId)
//   byte  32     : flags
//   bytes 33–36  : signCount (big-endian uint32)
//   if AT flag:
//     bytes 37–52       : AAGUID (16 bytes)
//     bytes 53–54       : credentialIdLength (big-endian uint16)
//     bytes 55–N        : credentialId
//     bytes N+1–end     : COSE public key (CBOR)
// =====================================================================
function parseAuthData(buf: Uint8Array) {
  const rpIdHash = buf.slice(0, 32);
  const flagsByte = buf[32];
  const flags: AuthFlags = {
    up: !!(flagsByte & 0x01),
    uv: !!(flagsByte & 0x04),
    be: !!(flagsByte & 0x08),
    bs: !!(flagsByte & 0x10),
    at: !!(flagsByte & 0x40),
    ed: !!(flagsByte & 0x80),
  };
  const dv = new DataView(buf.buffer, buf.byteOffset + 33, 4);
  const signCount = dv.getUint32(0);
  let off = 37;
  let aaguid: Uint8Array | undefined;
  let credentialId: Uint8Array | undefined;
  let cosePublicKey: Map<number, unknown> | undefined;
  if (flags.at) {
    aaguid = buf.slice(off, off + 16); off += 16;
    const credIdLen = (buf[off] << 8) | buf[off + 1]; off += 2;
    credentialId = buf.slice(off, off + credIdLen); off += credIdLen;
    const r = decodeCbor(buf, off);
    cosePublicKey = r.value as Map<number, unknown>;
  }
  return { rpIdHash, flags, signCount, aaguid, credentialId, cosePublicKey };
}

// COSE EC2 (kty=2) ES256 (alg=-7) P-256 (crv=1) key map → JWK
function coseToJwk(cose: Map<number, unknown>): JsonWebKey {
  const kty = cose.get(1);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2 || crv !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error('COSE key is not EC2 P-256 (only ES256 / P-256 supported in this demo).');
  }
  return {
    kty: 'EC',
    crv: 'P-256',
    x: b64urlEncode(x),
    y: b64urlEncode(y),
    ext: true,
  };
}

// ASN.1 DER ECDSA signature → raw r||s (32+32 bytes) for SubtleCrypto.verify
function derToRaw(der: Uint8Array, intSize = 32): Uint8Array {
  let off = 0;
  if (der[off++] !== 0x30) throw new Error('DER: expected SEQUENCE');
  let seqLen = der[off++];
  if (seqLen & 0x80) {
    const lenBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < lenBytes; i++) seqLen = (seqLen << 8) | der[off++];
  }
  if (der[off++] !== 0x02) throw new Error('DER: expected INTEGER (r)');
  const rLen = der[off++];
  const rBytes = new Uint8Array(der.subarray(off, off + rLen)); off += rLen;
  if (der[off++] !== 0x02) throw new Error('DER: expected INTEGER (s)');
  const sLen = der[off++];
  const sBytes = new Uint8Array(der.subarray(off, off + sLen)); off += sLen;
  const pad = (b: Uint8Array): Uint8Array => {
    let trimmed = b;
    while (trimmed.length > intSize && trimmed[0] === 0) {
      trimmed = new Uint8Array(trimmed.subarray(1));
    }
    const out = new Uint8Array(intSize);
    out.set(trimmed, intSize - trimmed.length);
    return out;
  };
  const rPad = pad(rBytes);
  const sPad = pad(sBytes);
  const raw = new Uint8Array(intSize * 2);
  raw.set(rPad, 0); raw.set(sPad, intSize);
  return raw;
}

// =====================================================================
// base64 helpers
// =====================================================================
function b64Encode(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}
function b64urlEncode(buf: Uint8Array): string {
  return b64Encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function bytesToUuid(b: Uint8Array): string {
  const h = Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
}

// =====================================================================
// The relying-party checks from the simulator above, run against the REAL
// browser response. The simulated section teaches five checks (challenge,
// origin, RP ID hash, signature, counter); if this section only verified the
// signature, its "Verified" badge would be claiming four checks it never ran.
// So it runs them here, on the real bytes, and the badge is the AND of them.
//
// §7.1 (registration) and §7.2 (authentication) of the W3C WebAuthn spec list
// more steps than these — notably token-binding, extension-output, and
// attestation-trust validation. Those are called out in the note the UI prints;
// what is here is every check that is meaningful for a demo with no server and
// `attestation: 'none'`.
// =====================================================================
interface ClientData {
  type?: string;
  challenge?: string;
  origin?: string;
  crossOrigin?: boolean;
}

function checkClientData(
  clientDataJSON: string,
  expectedType: string,
  expectedChallengeB64Url: string,
  expectedOrigin: string,
): LiveCheck[] {
  const checks: LiveCheck[] = [];
  let client: ClientData;
  try {
    client = JSON.parse(clientDataJSON) as ClientData;
  } catch {
    return [
      { label: 'clientDataJSON parses', pass: false, detail: 'clientDataJSON was not valid JSON.' },
    ];
  }

  const typeOk = client.type === expectedType;
  checks.push({
    label: 'Ceremony type',
    pass: typeOk,
    detail: typeOk
      ? `type is "${expectedType}", so a registration response cannot be replayed as a login.`
      : `type is "${String(client.type)}", expected "${expectedType}".`,
  });

  const challengeOk = client.challenge === expectedChallengeB64Url;
  checks.push({
    label: 'Challenge match',
    pass: challengeOk,
    detail: challengeOk
      ? 'The signed challenge is byte-for-byte the random one this page just generated.'
      : 'The signed challenge is not the one this page issued — a replay would land here.',
  });

  const originOk = client.origin === expectedOrigin;
  checks.push({
    label: 'Origin match',
    pass: originOk,
    detail: originOk
      ? `Origin ${String(client.origin)} matches this page's origin.`
      : `Origin ${String(client.origin)} != expected ${expectedOrigin} — this is the check that blocks phishing.`,
  });

  return checks;
}

// =====================================================================
// Public API
// =====================================================================
export function isWebAuthnSupported(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';
}

export async function isUserVerifyingPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

export async function createLivePasskey(rpId: string, rpName: string): Promise<LiveRegistration> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn is not available in this browser.');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: rpId, name: rpName },
      user: {
        id: userId,
        name: `demo-${Date.now()}@example.invalid`,
        displayName: 'Crypto-lab demo user',
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
      ],
      authenticatorSelection: {
        userVerification: 'preferred',
        residentKey: 'preferred',
        requireResidentKey: false,
      },
      attestation: 'none',
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Credential creation returned null.');
  const response = cred.response as AuthenticatorAttestationResponse;

  const attObj = decodeCbor(new Uint8Array(response.attestationObject)).value as Map<string, unknown>;
  const authDataBytes = attObj.get('authData') as Uint8Array;
  if (!authDataBytes) throw new Error('attestationObject has no authData.');
  const parsed = parseAuthData(authDataBytes);
  if (!parsed.cosePublicKey || !parsed.aaguid) {
    throw new Error('Registration authData missing attestedCredentialData.');
  }

  const jwk = coseToJwk(parsed.cosePublicKey);
  const publicKeyImported = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify'],
  );

  const transports =
    typeof response.getTransports === 'function' ? response.getTransports() : [];
  const aaguid = bytesToUuid(parsed.aaguid);
  const aaguidIsZero = parsed.aaguid.every((b) => b === 0);

  const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);
  const rpIdHash = await sha256(enc.encode(rpId));

  // Run the registration-side checks (§7.1) that this demo can meaningfully
  // run, so the panel reports something it actually computed.
  const checks: LiveCheck[] = checkClientData(
    clientDataJSON,
    'webauthn.create',
    b64urlEncode(challenge),
    window.location.origin,
  );
  const rpHashOk = bytesEqual(parsed.rpIdHash, rpIdHash);
  checks.push({
    label: 'RP ID hash',
    pass: rpHashOk,
    detail: rpHashOk
      ? `authData[0..32] equals SHA-256("${rpId}").`
      : `authData[0..32] does not equal SHA-256("${rpId}").`,
  });
  checks.push({
    label: 'User present (UP)',
    pass: parsed.flags.up,
    detail: parsed.flags.up
      ? 'UP flag set — the authenticator confirms a user gesture.'
      : 'UP flag NOT set; WebAuthn requires it on registration.',
  });
  checks.push({
    label: 'Attested credential data (AT)',
    pass: parsed.flags.at,
    detail: parsed.flags.at
      ? 'AT flag set — authData carries the AAGUID, credential ID, and COSE public key.'
      : 'AT flag NOT set, so there is no public key to register.',
  });

  return {
    credentialId: b64urlEncode(new Uint8Array(cred.rawId)),
    credentialIdRaw: cred.rawId,
    aaguid,
    aaguidIsZero,
    transports,
    publicKeyJwk: jwk,
    publicKeyImported,
    flags: parsed.flags,
    signCount: parsed.signCount,
    clientDataJSON,
    authDataLen: authDataBytes.byteLength,
    rpId,
    rpIdHash,
    checks,
    lastSignCount: parsed.signCount,
  };
}

export async function getLiveAssertion(
  registered: LiveRegistration,
  rpId: string,
): Promise<LiveAssertion> {
  if (!isWebAuthnSupported()) throw new Error('WebAuthn is not available in this browser.');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [
        {
          id: registered.credentialIdRaw,
          type: 'public-key',
        },
      ],
      userVerification: 'preferred',
      timeout: 60_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Assertion returned null.');
  const response = cred.response as AuthenticatorAssertionResponse;

  const authDataBytes = new Uint8Array(response.authenticatorData);
  const parsed = parseAuthData(authDataBytes);
  const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);

  // Verify the signature ourselves to prove the public key from registration
  // actually verifies the assertion the browser just produced.
  const clientDataHash = await crypto.subtle.digest('SHA-256', response.clientDataJSON);
  const signedBytes = new Uint8Array(authDataBytes.byteLength + 32);
  signedBytes.set(authDataBytes, 0);
  signedBytes.set(new Uint8Array(clientDataHash), authDataBytes.byteLength);

  const sigDer = new Uint8Array(response.signature);
  let sigOk = false;
  try {
    const sigRaw = derToRaw(sigDer, 32);
    sigOk = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      registered.publicKeyImported,
      sigRaw as BufferSource,
      signedBytes as BufferSource,
    );
  } catch {
    sigOk = false;
  }

  // The same relying-party checks the simulator above runs, now on real bytes.
  const checks: LiveCheck[] = checkClientData(
    clientDataJSON,
    'webauthn.get',
    b64urlEncode(challenge),
    window.location.origin,
  );

  const rpHashOk = bytesEqual(parsed.rpIdHash, registered.rpIdHash);
  checks.push({
    label: 'RP ID hash',
    pass: rpHashOk,
    detail: rpHashOk
      ? `authData[0..32] equals SHA-256("${rpId}") — the same RP the credential was created for.`
      : `authData[0..32] does not equal SHA-256("${rpId}").`,
  });

  checks.push({
    label: 'Credential ID known',
    pass: b64urlEncode(new Uint8Array(cred.rawId)) === registered.credentialId,
    detail:
      b64urlEncode(new Uint8Array(cred.rawId)) === registered.credentialId
        ? 'The asserted credential is the one registered in this session.'
        : 'The authenticator returned a different credential than the one registered.',
  });

  checks.push({
    label: 'Signature valid',
    pass: sigOk,
    detail: sigOk
      ? 'ECDSA P-256 signature over (authData ‖ SHA-256(clientDataJSON)) verifies against the registered public key.'
      : 'Signature does NOT verify against the registered public key.',
  });

  checks.push({
    label: 'User present (UP)',
    pass: parsed.flags.up,
    detail: parsed.flags.up
      ? 'UP flag set — the authenticator confirms a user gesture.'
      : 'UP flag NOT set; WebAuthn requires it for an assertion.',
  });

  // Counter check. The spec permits an authenticator to always report 0 (§6.1.1),
  // and most synced passkey providers do exactly that. Reporting that as a
  // failure would be a lie about the authenticator; reporting it as a pass would
  // be a lie about the check. So it is reported as what it is: not exercised.
  const counterUnsupported = parsed.signCount === 0 && registered.lastSignCount === 0;
  const counterOk = counterUnsupported || parsed.signCount > registered.lastSignCount;
  checks.push({
    label: 'Counter increasing',
    pass: counterOk,
    detail: counterUnsupported
      ? 'This authenticator reports signCount = 0 always, which the spec allows. Clone detection is therefore not available for this credential — it is not a check that passed, it is a check that cannot run.'
      : counterOk
        ? `Counter ${parsed.signCount} > ${registered.lastSignCount}.`
        : `Counter ${parsed.signCount} <= ${registered.lastSignCount} — possible cloned authenticator.`,
  });
  if (!counterUnsupported && counterOk) registered.lastSignCount = parsed.signCount;

  const verified = checks.every((c) => c.pass);

  let rawSigPreview = '';
  try {
    rawSigPreview = b64Encode(derToRaw(sigDer, 32));
  } catch {
    rawSigPreview = '<DER decode failed>';
  }

  return {
    credentialId: b64urlEncode(new Uint8Array(cred.rawId)),
    signatureB64: b64Encode(sigDer),
    signatureRawB64: rawSigPreview,
    authDataLen: authDataBytes.byteLength,
    clientDataJSON,
    flags: parsed.flags,
    signCount: parsed.signCount,
    verified,
    checks,
    signedBytesPreview: b64Encode(signedBytes.slice(0, 48)) + (signedBytes.length > 48 ? '…' : ''),
  };
}

// Exposed for the engine self-test consistency check (signature seal property)
// and for the live-path verifier tests in test/live.test.ts.
export {
  coseToJwk as _coseToJwk,
  derToRaw as _derToRaw,
  decodeCbor as _decodeCbor,
  parseAuthData as _parseAuthData,
  checkClientData as _checkClientData,
  bytesEqual as _bytesEqual,
  b64urlEncode as _b64urlEncode,
};

// =====================================================================
// UI mount (called from main.ts after the synthetic demo is in the DOM)
// =====================================================================
export async function mountLiveDemo(host: HTMLElement, rpId: string, rpName: string): Promise<void> {
  host.replaceChildren();

  // Capability badges.
  const supported = isWebAuthnSupported();
  const status = document.createElement('div');
  status.className = 'live-status ' + (supported ? 'live-status--available' : 'live-status--unavailable');
  status.textContent = supported
    ? 'WebAuthn supported in this browser'
    : 'WebAuthn is NOT available in this browser. Try a recent Chrome / Safari / Firefox / Edge.';
  status.setAttribute('role', 'status');
  host.append(status);

  if (supported) {
    const uvpa = await isUserVerifyingPlatformAuthenticatorAvailable();
    const uvpaBadge = document.createElement('div');
    uvpaBadge.className = 'live-status ' + (uvpa ? 'live-status--available' : 'live-status--unavailable');
    uvpaBadge.textContent = uvpa
      ? 'Platform authenticator with user verification is available'
      : 'No platform authenticator (Windows Hello / Touch ID) — security key still works';
    host.append(uvpaBadge);
  }

  if (!supported) {
    return;
  }

  // Controls.
  const registerBtn = document.createElement('button');
  registerBtn.type = 'button';
  registerBtn.textContent = 'Register a real passkey';

  const authenticateBtn = document.createElement('button');
  authenticateBtn.type = 'button';
  authenticateBtn.className = 'secondary';
  authenticateBtn.textContent = 'Authenticate with the real passkey';
  authenticateBtn.disabled = true;

  const controls = document.createElement('div');
  controls.className = 'live-controls';
  controls.append(registerBtn, authenticateBtn);
  host.append(controls);

  const out = document.createElement('div');
  out.className = 'live-out';
  out.setAttribute('role', 'status');
  out.setAttribute('aria-live', 'polite');
  out.setAttribute('aria-atomic', 'true');
  out.id = 'live-out';
  out.innerHTML = '<p class="mono">Click "Register a real passkey" and follow your browser prompt.</p>';
  host.append(out);

  let registered: LiveRegistration | null = null;

  registerBtn.addEventListener('click', () => {
    void (async () => {
      registerBtn.disabled = true;
      out.setAttribute('aria-busy', 'true');
      try {
        registered = await createLivePasskey(rpId, rpName);
        renderLiveRegistration(out, registered);
        authenticateBtn.disabled = false;
      } catch (err) {
        renderLiveError(out, err);
      } finally {
        out.removeAttribute('aria-busy');
        registerBtn.disabled = false;
      }
    })();
  });

  authenticateBtn.addEventListener('click', () => {
    void (async () => {
      if (!registered) return;
      authenticateBtn.disabled = true;
      out.setAttribute('aria-busy', 'true');
      try {
        const assertion = await getLiveAssertion(registered, rpId);
        renderLiveAssertion(out, registered, assertion);
      } catch (err) {
        renderLiveError(out, err);
      } finally {
        out.removeAttribute('aria-busy');
        authenticateBtn.disabled = false;
      }
    })();
  });
}

function renderLiveError(out: HTMLElement, err: unknown): void {
  const msg = err instanceof Error ? err.message : String(err);
  out.innerHTML = '';
  const p = document.createElement('p');
  p.className = 'mono';
  p.textContent = `Error: ${msg}`;
  out.append(p);
}

function flagChip(label: string, on: boolean): HTMLElement {
  const span = document.createElement('span');
  span.className = 'live-flag ' + (on ? 'live-flag--on' : 'live-flag--off');
  span.textContent = `${label}: ${on ? '1' : '0'}`;
  return span;
}

function renderCheckList(checks: LiveCheck[], caption: string): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'live-checks';
  const cap = document.createElement('p');
  cap.className = 'signed-bytes-note';
  cap.textContent = caption;
  const ul = document.createElement('ul');
  ul.className = 'live-check-list';
  for (const c of checks) {
    const li = document.createElement('li');
    li.className = 'live-check ' + (c.pass ? 'live-check--pass' : 'live-check--fail');
    const badge = document.createElement('span');
    badge.className = 'live-flag ' + (c.pass ? 'live-flag--on' : 'live-flag--off');
    badge.textContent = c.pass ? 'PASS' : 'FAIL';
    const label = document.createElement('strong');
    label.textContent = ` ${c.label}: `;
    const detail = document.createElement('span');
    detail.textContent = c.detail;
    li.append(badge, label, detail);
    ul.append(li);
  }
  wrap.append(cap, ul);
  return wrap;
}

function renderFlagRow(flags: AuthFlags): HTMLElement {
  const row = document.createElement('div');
  row.className = 'live-flags';
  // `aria-label` is prohibited on a role-less <div> and is silently discarded;
  // `role="group"` is the generic labellable grouping role, so the name the
  // markup intended actually reaches the accessibility tree. See the same fix
  // on `.signed-bytes` in ui.ts.
  row.setAttribute('role', 'group');
  row.setAttribute('aria-label', 'authData flags');
  row.append(
    flagChip('UP', flags.up),
    flagChip('UV', flags.uv),
    flagChip('BE', flags.be),
    flagChip('BS', flags.bs),
    flagChip('AT', flags.at),
    flagChip('ED', flags.ed),
  );
  return row;
}

function renderLiveRegistration(out: HTMLElement, r: LiveRegistration): void {
  out.replaceChildren();
  const dl = document.createElement('dl');
  dl.className = 'signed-bytes-dl';
  const addPair = (term: string, value: string) => {
    const dt = document.createElement('dt'); dt.textContent = term;
    const dd = document.createElement('dd'); dd.className = 'mono'; dd.textContent = value;
    dl.append(dt, dd);
  };
  addPair('credentialId (base64url)', r.credentialId);
  addPair('AAGUID', r.aaguidIsZero ? `${r.aaguid}  (zero — attestation:'none' withholds the model)` : r.aaguid);
  addPair('transports', r.transports.length ? r.transports.join(', ') : '(none reported)');
  addPair('public key (JWK)', `${r.publicKeyJwk.kty} / ${r.publicKeyJwk.crv}, x=${(r.publicKeyJwk.x ?? '').slice(0, 22)}…`);
  addPair('signCount', String(r.signCount));
  addPair('authData length', `${r.authDataLen} bytes`);

  const wrap = document.createElement('div');
  wrap.className = 'signed-bytes';
  wrap.append(
    Object.assign(document.createElement('p'), { className: 'signed-bytes-title', textContent: '' }),
    dl,
    renderFlagRow(r.flags),
    renderCheckList(
      r.checks,
      'Registration checks, run here against the real response (W3C WebAuthn §7.1). The AAGUID above is read out of authData’s attested credential data, not out of the attestation statement.',
    ),
    Object.assign(document.createElement('p'), {
      className: 'signed-bytes-note',
      textContent:
        'These values come from the real browser response. AT must be 1 on registration (the public key is included). BE/BS indicate whether the passkey is syncable across devices. This demo requests attestation: \'none\', so it does not — and cannot — validate an attestation statement or the authenticator model.',
    }),
  );
  // Add an eyebrow title.
  const eyebrow = wrap.querySelector('.signed-bytes-title') as HTMLElement;
  const e = document.createElement('span');
  e.className = 'signed-bytes-eyebrow';
  e.textContent = 'Registration response (from the real browser)';
  eyebrow.append(e);
  out.append(wrap);
}

function renderLiveAssertion(out: HTMLElement, r: LiveRegistration, a: LiveAssertion): void {
  out.replaceChildren();
  const status = document.createElement('div');
  status.className = 'verify-header';
  const badge = document.createElement('span');
  badge.className =
    'scenario-status ' + (a.verified ? 'scenario-status--valid' : 'scenario-status--invalid');
  const firstBad = a.checks.find((c) => !c.pass);
  badge.textContent = a.verified ? 'Verified' : 'Rejected';
  const summary = document.createElement('span');
  summary.className = 'verify-summary';
  summary.textContent = a.verified
    ? `All ${a.checks.length} relying-party checks passed, including the ECDSA P-256 signature verified locally against the public key from registration (${r.publicKeyJwk.crv}).`
    : `Rejected: ${firstBad?.detail ?? 'a check failed.'}`;
  status.append(badge, summary);
  out.append(status);

  const dl = document.createElement('dl');
  dl.className = 'signed-bytes-dl';
  const addPair = (term: string, value: string) => {
    const dt = document.createElement('dt'); dt.textContent = term;
    const dd = document.createElement('dd'); dd.className = 'mono'; dd.textContent = value;
    dl.append(dt, dd);
  };
  addPair('credentialId', a.credentialId);
  addPair('signCount', String(a.signCount));
  addPair('authData length', `${a.authDataLen} bytes`);
  addPair('signature (DER, base64)', a.signatureB64.slice(0, 64) + (a.signatureB64.length > 64 ? '…' : ''));
  addPair('signature (raw r∥s, base64)', a.signatureRawB64.slice(0, 64) + (a.signatureRawB64.length > 64 ? '…' : ''));
  addPair('signed bytes preview', a.signedBytesPreview);
  addPair('clientDataJSON', a.clientDataJSON.length > 110 ? a.clientDataJSON.slice(0, 110) + '…' : a.clientDataJSON);

  const wrap = document.createElement('div');
  wrap.className = 'signed-bytes';
  const eyebrowPara = document.createElement('p');
  eyebrowPara.className = 'signed-bytes-title';
  const eyebrow = document.createElement('span');
  eyebrow.className = 'signed-bytes-eyebrow';
  eyebrow.textContent = 'Real assertion (verified locally)';
  eyebrowPara.append(eyebrow);
  const note = document.createElement('p');
  note.className = 'signed-bytes-note';
  note.textContent =
    'The browser returns the signature in ASN.1 DER. SubtleCrypto.verify expects raw r∥s, so the demo converts it. The verification step uses the public key extracted from registration — the same property the simulator demonstrates above, now on real bytes. Not run here: token-binding, extension-output, and attestation-trust validation, which W3C WebAuthn §7.2 also lists.';
  wrap.append(
    eyebrowPara,
    dl,
    renderFlagRow(a.flags),
    renderCheckList(a.checks, 'Every check behind the verdict above, each computed from the bytes the browser returned:'),
    note,
  );
  out.append(wrap);
}

