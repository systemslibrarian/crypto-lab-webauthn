// ui.ts — renders the WebAuthn passkey demo. All crypto is delegated to engine.ts.
import {
  Authenticator,
  RelyingParty,
  randomChallenge,
  shortB64,
  type Assertion,
  type StoredCredential,
  type VerifyResult,
} from './engine';
import {
  CEREMONY_STEPS,
  WHY_PHISHING_FAILS,
  PASSWORD_VS_PASSKEY,
  REAL_WORLD,
  SCRIPTURE_TEXT,
  SCRIPTURE_CITATION,
} from './data';

// Tiny DOM helper in the sibling-demo style.
type Attrs = Record<string, string | boolean | number | undefined> & {
  text?: string;
  html?: string;
  on?: Record<string, EventListener>;
};
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { text, html, on, ...rest } = attrs;
  for (const [k, v] of Object.entries(rest)) {
    if (v === undefined || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (k.startsWith('data-') || k === 'role' || k === 'aria-label' || k === 'aria-live') {
      node.setAttribute(k, String(v));
    } else if (k === 'id') node.id = String(v);
    else node.setAttribute(k, String(v));
  }
  if (text !== undefined) node.textContent = text;
  if (html !== undefined) node.innerHTML = html;
  if (on) for (const [ev, fn] of Object.entries(on)) node.addEventListener(ev, fn);
  for (const c of children) node.append(c);
  return node;
}

// ---- demo constants ----
const RP_ID = 'example.com';
const ORIGIN_REAL = 'https://example.com';
const ORIGIN_PHISH = 'https://examp1e-login.com';
const RP_ID_EVIL = 'evil.com';

// ---- demo state held in closure across the whole UI ----
interface DemoState {
  auth: Authenticator;
  rp: RelyingParty;
  credential: StoredCredential | null;
  lastAssertion: Assertion | null;
  lastChallenge: string | null;
}

export function mountApp(root: HTMLDivElement): void {
  const state: DemoState = {
    auth: new Authenticator(),
    rp: new RelyingParty(),
    credential: null,
    lastAssertion: null,
    lastChallenge: null,
  };

  root.append(
    renderHero(),
    renderRegister(state),
    renderLogin(state),
    renderBreakIt(state),
    renderPhishingExplainer(),
    renderComparison(),
    renderRealWorld(),
    renderFooter(),
  );
}

// =====================================================================
// Hero
// =====================================================================
function renderHero(): HTMLElement {
  const section = el('section', { class: 'hero-panel' });

  const toggle = el('button', {
    class: 'theme-toggle',
    id: 'theme-toggle',
    type: 'button',
    'aria-label': 'Toggle dark and light theme',
    text: '🌙',
  });
  section.append(toggle);

  section.append(
    el('p', { class: 'hero-eyebrow', text: 'Authentication · Passkeys' }),
    el('h1', { text: 'WebAuthn passkeys — login without a shared secret' }),
    el('p', {
      class: 'hero-lede',
      text:
        'Passwords are shared secrets you type into whatever page asks. Phishing works because that page does not have to be the real one. Passkeys flip the model: your authenticator keeps a private key per site, signs each login with the origin baked in, and the server only ever stores a public key. Below: a real ECDSA P-256 ceremony, then four attacks that bounce off it.',
    }),
  );

  const details = el('details');
  details.append(
    el('summary', { text: 'How is this different from a password?' }),
    el('p', {
      text:
        'With a password, the server holds a secret (a hash) that has to match what you type. A phishing page can collect the typed secret and replay it. With a passkey, there is no shared secret at all — the server has a public key, the authenticator has the matching private key, and every login is a fresh challenge that the authenticator signs along with the actual origin the browser saw.',
    }),
  );
  section.append(details);

  section.append(
    el('div', {
      class: 'hero-metric',
      text: 'Real ECDSA P-256 · private key never leaves the authenticator · phishing-resistant',
    }),
  );

  return section;
}

// =====================================================================
// Phase 2 — Register a passkey
// =====================================================================
function renderRegister(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'register' });

  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'Register a passkey' }),
      el('span', { class: 'section-kicker', text: 'Ceremony · step 1' }),
    ]),
    el('p', {
      text:
        'The authenticator generates a fresh ECDSA P-256 keypair bound to the relying party (example.com). It returns the public key — that is all the server keeps. The private key never leaves the authenticator.',
    }),
  );

  const out = el('div', { class: 'panel-card', id: 'register-out' });
  out.append(el('p', { class: 'mono', text: 'No credential yet. Click "Create passkey".' }));

  const button = el('button', { type: 'button', text: 'Create passkey' });
  button.addEventListener('click', () => {
    void (async () => {
      button.disabled = true;
      try {
        const cred = await state.auth.makeCredential(RP_ID);
        state.rp.register(cred);
        state.credential = cred;
        state.lastAssertion = null;
        state.lastChallenge = null;
        renderCredential(out, cred);
      } catch (err) {
        out.replaceChildren(
          el('p', { class: 'mono', text: `Error: ${(err as Error).message}` }),
        );
      } finally {
        button.disabled = false;
      }
    })();
  });

  section.append(el('div', { class: 'playground-grid' }, [
    el('div', { class: 'panel-card' }, [
      el('p', { text: 'Generate a new credential keypair on this simulated authenticator.' }),
      button,
    ]),
    out,
  ]));

  return section;
}

function renderCredential(container: HTMLElement, cred: StoredCredential): void {
  container.replaceChildren();
  const kty = cred.publicKeyJwk.kty ?? '?';
  const crv = cred.publicKeyJwk.crv ?? '?';
  const x = cred.publicKeyJwk.x ? shortB64(cred.publicKeyJwk.x, 22) : '?';
  const y = cred.publicKeyJwk.y ? shortB64(cred.publicKeyJwk.y, 22) : '?';

  const table = el('table', { class: 'math-table' });
  table.append(
    rowTH('Stored credential', 'value (truncated)'),
    row('Credential ID', shortB64(cred.credentialId, 22)),
    row('RP ID', cred.rpId),
    row('Public key (kty / crv)', `${kty} / ${crv}`),
    row('Public key x', x),
    row('Public key y', y),
    row('signCount', String(cred.signCount)),
  );
  container.append(
    table,
    el('p', {
      class: 'mono',
      text: 'The server stores all of this. It has no copy of the private key — there is no secret on the server to steal.',
    }),
  );
}

function rowTH(a: string, b: string): HTMLTableRowElement {
  const r = el('tr');
  r.append(el('th', { text: a }), el('th', { text: b }));
  return r;
}
function row(a: string, b: string): HTMLTableRowElement {
  const r = el('tr');
  r.append(el('td', { text: a }), el('td', { class: 'mono', text: b }));
  return r;
}

// =====================================================================
// Phase 3 — Authenticate
// =====================================================================
function renderLogin(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'login' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'Log in' }),
      el('span', { class: 'section-kicker', text: 'Ceremony · step 2' }),
    ]),
    el('p', {
      text:
        'The server issues a fresh challenge. The authenticator signs (challenge ‖ origin ‖ rpIdHash ‖ counter) with the private key. The server verifies the signature with the stored public key and checks every contextual field.',
    }),
  );

  const out = el('div', { class: 'panel-card', id: 'login-out' });
  out.append(el('p', { class: 'mono', text: 'No login yet. Register first, then click "Authenticate".' }));

  const button = el('button', { type: 'button', text: 'Authenticate' });
  button.addEventListener('click', () => {
    void (async () => {
      if (!state.credential) {
        renderChecksError(out, 'Register a passkey first.');
        return;
      }
      button.disabled = true;
      try {
        const challenge = randomChallenge();
        const assertionOrErr = await state.auth.getAssertion(
          state.credential.credentialId,
          challenge,
          ORIGIN_REAL,
          RP_ID,
        );
        if ('error' in assertionOrErr) {
          renderChecksError(out, assertionOrErr.error);
          return;
        }
        const result = await state.rp.verifyAssertion(assertionOrErr, {
          expectedChallenge: challenge,
          expectedOrigin: ORIGIN_REAL,
          expectedRpId: RP_ID,
        });
        state.lastAssertion = assertionOrErr;
        state.lastChallenge = challenge;
        renderVerifyResult(out, result, { challenge, origin: ORIGIN_REAL, rpId: RP_ID });
      } catch (err) {
        renderChecksError(out, `Unexpected error: ${(err as Error).message}`);
      } finally {
        button.disabled = false;
      }
    })();
  });

  section.append(el('div', { class: 'playground-grid' }, [
    el('div', { class: 'panel-card' }, [
      el('p', { text: 'Issue a fresh challenge from the relying party, sign it with the credential, verify on the server.' }),
      button,
    ]),
    out,
  ]));

  return section;
}

interface VerifyMeta {
  challenge: string;
  origin: string;
  rpId: string;
  note?: string;
}

function renderVerifyResult(container: HTMLElement, result: VerifyResult, meta: VerifyMeta): void {
  container.replaceChildren();

  const overallBadge = el('span', {
    class: `scenario-status ${result.ok ? 'scenario-status--valid' : 'scenario-status--invalid'}`,
    text: result.ok ? 'Authenticated' : 'Rejected',
  });
  container.append(
    el('div', { class: 'verify-header' }, [
      overallBadge,
      el('span', { class: 'verify-summary', text: result.summary }),
    ]),
  );

  const ctxBlock = el('table', { class: 'math-table' });
  ctxBlock.append(
    rowTH('Verifier context', 'value'),
    row('expectedChallenge', shortB64(meta.challenge, 22)),
    row('expectedOrigin', meta.origin),
    row('expectedRpId', meta.rpId),
  );
  container.append(ctxBlock);

  const list = el('ul', { class: 'check-list' });
  for (const c of result.checks) {
    const li = el('li', { class: `check-row ${c.pass ? 'check-row--pass' : 'check-row--fail'}` });
    li.append(
      el('span', {
        class: `scenario-status ${c.pass ? 'scenario-status--valid' : 'scenario-status--invalid'}`,
        text: c.pass ? 'pass' : 'fail',
      }),
      el('span', { class: 'check-label', text: c.label }),
      el('span', { class: 'check-detail', text: c.detail }),
    );
    list.append(li);
  }
  container.append(list);

  if (meta.note) {
    container.append(el('p', { class: 'verify-note mono', text: meta.note }));
  }
}

function renderChecksError(container: HTMLElement, message: string): void {
  container.replaceChildren(
    el('div', { class: 'verify-header' }, [
      el('span', { class: 'scenario-status scenario-status--invalid', text: 'Rejected' }),
      el('span', { class: 'verify-summary', text: message }),
    ]),
  );
}

// =====================================================================
// Phase 4 — Break it
// =====================================================================
function renderBreakIt(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'break-it' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'Break it (and watch each attack fail)' }),
      el('span', { class: 'section-kicker', text: 'The payoff' }),
    ]),
    el('p', {
      text:
        'Each control re-runs authentication under a specific attack. Look at WHICH check fails — that is what makes the design phishing-resistant.',
    }),
  );

  const out = el('div', { class: 'panel-card', id: 'attack-out' });
  out.append(el('p', { class: 'mono', text: 'No attack run yet. Pick one of the controls.' }));

  const phishBtn = el('button', { type: 'button', class: 'secondary', text: '👻 Phishing site' });
  const replayBtn = el('button', { type: 'button', class: 'secondary', text: '🔁 Replay assertion' });
  const wrongRpBtn = el('button', { type: 'button', class: 'secondary', text: '🪤 Wrong relying party' });
  const cloneBtn = el('button', { type: 'button', class: 'secondary', text: '👯 Cloned authenticator' });
  const baselineBtn = el('button', { type: 'button', class: 'secondary', text: '↺ Reset baseline' });

  phishBtn.addEventListener('click', () => void runPhishing(state, out, phishBtn));
  replayBtn.addEventListener('click', () => void runReplay(state, out, replayBtn));
  wrongRpBtn.addEventListener('click', () => void runWrongRp(state, out, wrongRpBtn));
  cloneBtn.addEventListener('click', () => void runClone(state, out, cloneBtn));
  baselineBtn.addEventListener('click', () => void runBaseline(state, out, baselineBtn));

  section.append(
    el('div', { class: 'playground-grid' }, [
      el('div', { class: 'panel-card attack-controls' }, [
        el('p', { text: 'Run an attack against the registered credential. Each restores cleanly so you can try the next.' }),
        el('div', { class: 'attack-button-row' }, [phishBtn, replayBtn, wrongRpBtn, cloneBtn]),
        el('div', { class: 'attack-button-row' }, [baselineBtn]),
      ]),
      out,
    ]),
  );

  return section;
}

async function runPhishing(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  btn.disabled = true;
  try {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential.credentialId,
      challenge,
      ORIGIN_PHISH,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    renderVerifyResult(out, result, {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: `Authenticator signed origin ${ORIGIN_PHISH}; verifier expected ${ORIGIN_REAL}. The look-alike domain cannot produce a usable assertion because the real origin is baked into what gets signed.`,
    });
  } finally {
    btn.disabled = false;
  }
}

async function runReplay(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  btn.disabled = true;
  try {
    const challenge1 = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential.credentialId,
      challenge1,
      ORIGIN_REAL,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    // First verify passes — capture the assertion.
    const first = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: challenge1,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    if (!first.ok) {
      renderVerifyResult(out, first, { challenge: challenge1, origin: ORIGIN_REAL, rpId: RP_ID });
      return;
    }
    // Now replay against a NEW challenge.
    const challenge2 = randomChallenge();
    const replayed = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: challenge2,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    renderVerifyResult(out, replayed, {
      challenge: challenge2,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: 'A valid assertion was captured and replayed against a fresh challenge. The signed challenge does not match the new one — replay blocked.',
    });
  } finally {
    btn.disabled = false;
  }
}

async function runWrongRp(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  btn.disabled = true;
  try {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential.credentialId,
      challenge,
      `https://${RP_ID_EVIL}`,
      RP_ID_EVIL,
    );
    if ('error' in assertionOrErr) {
      out.replaceChildren(
        el('div', { class: 'verify-header' }, [
          el('span', { class: 'scenario-status scenario-status--invalid', text: 'Refused by authenticator' }),
          el('span', { class: 'verify-summary', text: assertionOrErr.error }),
        ]),
        el('p', {
          class: 'verify-note mono',
          text: `Credential is bound to ${RP_ID}; the authenticator will not produce an assertion for ${RP_ID_EVIL}. The verifier never even sees a signature.`,
        }),
      );
      return;
    }
    // (Should not get here — kept for type-safety.)
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    renderVerifyResult(out, result, { challenge, origin: ORIGIN_REAL, rpId: RP_ID });
  } finally {
    btn.disabled = false;
  }
}

async function runClone(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  btn.disabled = true;
  try {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    // Simulate a clone: same private key reused, but the clone's local counter
    // has not advanced as far. Force signCount <= last seen.
    const cloned: Assertion = { ...assertionOrErr, signCount: 0 };
    const result = await state.rp.verifyAssertion(cloned, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    renderVerifyResult(out, result, {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: 'A clone of the authenticator would lag behind on the monotonic counter. The server sees signCount go backwards and flags it — clone detection.',
    });
  } finally {
    btn.disabled = false;
  }
}

async function runBaseline(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  btn.disabled = true;
  try {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: challenge,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    renderVerifyResult(out, result, {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: 'Baseline restored: a clean authentication against the real relying party with a fresh challenge.',
    });
  } finally {
    btn.disabled = false;
  }
}

// =====================================================================
// Phase 5 — Why phishing fails / comparison
// =====================================================================
function renderPhishingExplainer(): HTMLElement {
  const section = el('section', { class: 'lab-section' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'Why phishing fails' }),
      el('span', { class: 'section-kicker', text: 'The security property' }),
    ]),
    el('p', {
      text:
        'A passkey login has four properties working together. Even one of them stops the common phishing attack — they reinforce each other.',
    }),
  );

  const grid = el('div', { class: 'reuse-grid' });
  for (const card of WHY_PHISHING_FAILS) {
    grid.append(
      el('div', { class: 'panel-card' }, [
        el('h3', { class: 'card-title', text: card.title }),
        el('p', { text: card.body }),
      ]),
    );
  }
  section.append(grid);

  section.append(
    el('div', { class: 'section-heading-row', style: 'margin-top:28px' }, [
      el('h2', { text: 'Passwords vs passkeys' }),
      el('span', { class: 'section-kicker', text: 'At a glance' }),
    ]),
  );
  const table = el('table', { class: 'math-table' });
  const head = el('tr');
  head.append(
    el('th', { text: 'Property' }),
    el('th', { text: 'Password' }),
    el('th', { text: 'Passkey' }),
  );
  table.append(head);
  for (const r of PASSWORD_VS_PASSKEY) {
    const tr = el('tr');
    tr.append(
      el('td', { text: r.property }),
      el('td', { text: r.password }),
      el('td', { text: r.passkey }),
    );
    table.append(tr);
  }
  section.append(table);

  return section;
}

function renderComparison(): HTMLElement {
  const section = el('section', { class: 'lab-section' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'The ceremony at a glance' }),
      el('span', { class: 'section-kicker', text: 'Step by step' }),
    ]),
    el('p', {
      text: 'Every step that touches a secret happens inside the authenticator. The server only ever sees public material.',
    }),
  );
  const table = el('table', { class: 'math-table' });
  const head = el('tr');
  head.append(
    el('th', { text: 'Phase' }),
    el('th', { text: '#' }),
    el('th', { text: 'Actor' }),
    el('th', { text: 'What happens' }),
  );
  table.append(head);
  for (const s of CEREMONY_STEPS) {
    const tr = el('tr');
    tr.append(
      el('td', { text: s.phase }),
      el('td', { class: 'mono', text: String(s.ordinal) }),
      el('td', { text: s.actor }),
      el('td', { text: s.action }),
    );
    table.append(tr);
  }
  section.append(table);
  return section;
}

// =====================================================================
// Phase 6 — In the real world
// =====================================================================
function renderRealWorld(): HTMLElement {
  const section = el('section', { class: 'lab-section' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { text: 'In the real world' }),
      el('span', { class: 'section-kicker', text: 'Beyond the toy model' }),
    ]),
    el('p', {
      text:
        'How a deployed WebAuthn login differs from this page, in honest terms.',
    }),
  );
  const grid = el('div', { class: 'reuse-grid' });
  for (const note of REAL_WORLD) {
    grid.append(
      el('div', { class: 'panel-card' }, [
        el('h3', { class: 'card-title', text: note.title }),
        el('p', { text: note.body }),
      ]),
    );
  }
  section.append(grid);
  return section;
}

// =====================================================================
// Footer — scripture (Part D)
// =====================================================================
function renderFooter(): HTMLElement {
  const footer = el('footer', { class: 'scripture-footer' });
  footer.append(
    el('p', { text: SCRIPTURE_TEXT }),
    el('cite', { text: `— ${SCRIPTURE_CITATION}` }),
  );
  return footer;
}
