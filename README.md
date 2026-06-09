# crypto-lab-webauthn

## What It Is

A faithful model of the WebAuthn / FIDO2 passkey ceremony using **real ECDSA P-256 signatures** via the browser's Web Crypto API. A simulated authenticator generates a credential keypair bound to a relying party (RP), keeps the private key inside itself, and produces signed assertions on demand. A simulated server registers the public credential and verifies each assertion against five contextual checks: a fresh challenge, the origin the browser actually saw, the RP ID hash, the ECDSA signature itself, and a monotonic counter for clone detection. The same engine then drives four attacks — a phishing site, a replayed assertion, a wrong-relying-party request, and a cloned authenticator — so you can watch the specific check each attack trips on. This is **not** the full CBOR/COSE/attestation wire format; it models the *security-relevant logic* of WebAuthn — the parts you'd review in a relying-party verifier — without the byte-level encoding work that production libraries already do.

## When to Use It

- **Teaching how passkeys actually log you in** — show the registration vs. authentication ceremonies without hand-waving over the math, because the page is doing real ECDSA P-256.
- **Explaining *why* WebAuthn is phishing-resistant** — the "Phishing site" control signs with a look-alike origin and watches the server's Origin check reject it. That's the whole anti-phishing property, made visible.
- **Auditing or building a relying-party verifier** — the five checks (challenge, origin, RP ID hash, signature, counter) are the same five your verifier has to run; here they are with passing/failing detail per row.
- **Comparing passwords vs. passkeys in front of a non-cryptographer audience** — there is a shared-secret table you can point at, plus a working demo of "no secret on the server".
- **Reference: in production, use these** — the platform `navigator.credentials.create` / `.get` APIs and a vetted server library (SimpleWebAuthn, py_webauthn, webauthn4j, fido2-net-lib). Use real attestation when you need it. This page is for learning.
- **Do NOT use this demo's JSON authData / clientData encoding for anything** — it stands in for CBOR-encoded WebAuthn structures so the security logic is readable. The cryptography is real; the encoding is not.

## Live Demo

[**https://systemslibrarian.github.io/crypto-lab-webauthn/**](https://systemslibrarian.github.io/crypto-lab-webauthn/)

The page is built around a single register-then-authenticate flow followed by four attacks. **Create passkey** generates a fresh ECDSA P-256 keypair on the simulated authenticator and registers the public half with the simulated server. **Authenticate** issues a new challenge, signs `(challenge ‖ origin ‖ rpIdHash ‖ counter)`, and prints every server-side check with a pass/fail badge plus the verifier context (expectedChallenge, expectedOrigin, expectedRpId). The **Break it** controls re-run the ceremony four ways: **Phishing site** signs with `https://examp1e-login.com` while the server still expects `https://example.com` — the Origin check fails. **Replay** captures a valid assertion, verifies it once successfully, then verifies the same assertion against a fresh challenge — the Challenge check fails. **Wrong relying party** asks the authenticator for an assertion for `evil.com` — the authenticator itself refuses, and the server never sees a signature. **Cloned authenticator** lowers the counter on a fresh assertion to simulate a clone whose local count has fallen behind — the Counter check fails. A reset baseline button always restores a clean authentication so you can try the next attack.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-webauthn.git
cd crypto-lab-webauthn
npm install
npm run dev      # local dev server with HMR
npm run build    # type-check + production build to dist/
npm run preview  # serve the built dist/ locally
```

No environment variables, no API keys, no servers. Everything runs client-side in the browser against Web Crypto.

## Part of the Crypto-Lab Suite

This is one demo in a wider portfolio of interactive cryptography labs — see [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/) for the rest, including the five PQC families overview, hybrid TLS, harvest-now-decrypt-later timelines, key-exchange generations, and deep-dives on individual schemes.

---

"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31
