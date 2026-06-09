// ui.ts — renders the WebAuthn passkey demo. All crypto is delegated to engine.ts.
import {
  Authenticator,
  RelyingParty,
  randomChallenge,
  shortB64,
  AUTH_FLAG_UP,
  AUTH_FLAG_UV,
  type Assertion,
  type StoredCredential,
  type VerifyResult,
} from './engine';
import {
  CEREMONY_STEPS,
  WHY_PHISHING_FAILS,
  PASSWORD_VS_PASSKEY,
  REAL_WORLD,
  PRODUCTION_GAPS,
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
    else if (
      k.startsWith('data-') ||
      k.startsWith('aria-') ||
      k === 'role' ||
      k === 'tabindex'
    ) {
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
interface BaselineSnapshot {
  assertion: Assertion;
  result: VerifyResult;
  meta: VerifyMeta;
}
interface DemoState {
  auth: Authenticator;
  rp: RelyingParty;
  credential: StoredCredential | null;
  signCountChip: HTMLElement | null;
  lastBaseline: BaselineSnapshot | null;
}

interface VerifyMeta {
  challenge: string;
  origin: string;
  rpId: string;
  note?: string;
  label?: string; // shown above the result in side-by-side mode
}

function updateSignCountChip(state: DemoState): void {
  const chip = state.signCountChip;
  if (!chip || !state.credential) return;
  const current = state.auth.peekCount(state.credential.credentialId);
  const strong = chip.querySelector('strong');
  if (strong) strong.textContent = String(current);
  chip.classList.remove('bumped');
  void chip.offsetWidth;
  chip.classList.add('bumped');
}

export function mountApp(root: HTMLDivElement): void {
  const state: DemoState = {
    auth: new Authenticator(),
    rp: new RelyingParty(),
    credential: null,
    signCountChip: null,
    lastBaseline: null,
  };

  const hero = renderHero(state);
  const main = el('main', { id: 'main-content', role: 'main', tabindex: '-1' });
  main.append(
    renderCeremonyDiagram(),
    renderRegister(state),
    renderLogin(state),
    renderBreakIt(state),
    renderTamperPanel(state),
    renderDiscoverableUV(state),
    renderPhishingExplainer(),
    renderCeremonyTable(),
    renderRealWorld(),
    renderProductionGaps(),
    renderLiveDemo(),
  );
  root.append(hero, main, renderFooter());
}

// =====================================================================
// Production gaps (Path A — honest boundary)
// =====================================================================
function renderProductionGaps(): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'production-gaps', 'aria-labelledby': 'gaps-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'gaps-h', text: 'What this teaching demo does not show' }),
      el('span', { class: 'section-kicker', text: 'Honest boundary' }),
    ]),
    el('p', {
      text:
        'A production WebAuthn relying party does more than verify a signature against five context fields. The six items below are the standard "gold-standard rubric" — what this page deliberately models, what the simulator extends (Path B, the discoverable / UV controls in the Log-in section), and what only the real browser API can give you (Path C, at the bottom of the page).',
    }),
  );

  const grid = el('div', { class: 'reuse-grid reuse-grid--two-col' });
  for (const gap of PRODUCTION_GAPS) {
    grid.append(
      el('div', { class: 'panel-card gap-card' }, [
        el('h3', { class: 'card-title', text: gap.title }),
        el('p', { class: 'gap-what', text: gap.what }),
        el('p', { class: 'gap-why' }, [
          el('strong', { text: 'In this demo: ' }),
          document.createTextNode(gap.why),
        ]),
        el('p', { class: 'gap-real' }, [
          el('strong', { text: 'In production: ' }),
          document.createTextNode(gap.doRealLibraries),
        ]),
      ]),
    );
  }
  section.append(grid);
  return section;
}

// =====================================================================
// Real WebAuthn live demo (Path C) — mounted by live.ts at runtime
// =====================================================================
function renderLiveDemo(): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'live-demo', 'aria-labelledby': 'live-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'live-h', text: 'Try it with a real passkey' }),
      el('span', { class: 'section-kicker', text: 'Real navigator.credentials' }),
    ]),
    el('p', {
      text:
        'Everything above uses a simulated authenticator so the bytes are readable. This section calls the actual browser WebAuthn API. If your device has a passkey provider (Apple, Google, Windows Hello, a security key), you can register a credential and authenticate against it for real — and see the actual AAGUID, BE/BS flags, and transports the browser reports.',
    }),
    el('div', { class: 'panel-card', id: 'live-demo-host' }, [
      el('p', { class: 'mono', text: 'Loading the live-demo module…' }),
    ]),
  );
  return section;
}

// =====================================================================
// Hero
// =====================================================================
function renderHero(state: DemoState): HTMLElement {
  const section = el('header', { class: 'hero-panel', role: 'banner' });

  const toggle = el('button', {
    class: 'theme-toggle',
    id: 'theme-toggle',
    type: 'button',
    'aria-label': 'Switch to light theme',
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

  const metricRow = el('div', { class: 'hero-metric-row' });
  metricRow.append(
    el('div', {
      class: 'hero-metric',
      text: 'Real ECDSA P-256 · private key never leaves the authenticator · phishing-resistant',
    }),
  );

  const chip = el('div', {
    class: 'sign-count-chip',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Authenticator signature counter',
  });
  chip.append(
    document.createTextNode('Authenticator signCount: '),
    el('strong', { text: '0' }),
  );
  state.signCountChip = chip;
  metricRow.append(chip);
  section.append(metricRow);

  return section;
}

// =====================================================================
// Ceremony diagram (the missing visual)
// =====================================================================
function renderCeremonyDiagram(): HTMLElement {
  const section = el('section', {
    class: 'lab-section',
    id: 'ceremony-diagram',
    'aria-labelledby': 'diag-h',
  });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'diag-h', text: 'What gets signed' }),
      el('span', { class: 'section-kicker', text: 'The whole concept in one picture' }),
    ]),
    el('p', {
      text:
        'The authenticator holds a private key that never leaves. To log in, it signs a packet of bytes that includes the origin the browser actually saw. The server, holding only the matching public key, verifies the signature and re-checks every field. Change anything about those bytes — origin, counter, challenge — and the signature stops verifying. That is the entire anti-phishing property.',
    }),
  );

  const diagram = el('div', {
    class: 'ceremony-diagram',
    role: 'group',
    'aria-label': 'Diagram of authenticator and server roles in a passkey login',
  });

  // Authenticator card
  const authCard = el('div', { class: 'ceremony-actor ceremony-actor--auth' });
  authCard.append(
    el('div', { class: 'ceremony-actor-title' }, [
      el('span', { class: 'ceremony-actor-icon', 'aria-hidden': 'true', text: '🔐' }),
      el('h3', { text: 'Authenticator' }),
    ]),
    el('p', { class: 'ceremony-secret', text: 'private key — never leaves the device' }),
    el('p', { class: 'ceremony-action mono' }, [
      document.createTextNode('sign('),
      el('span', { class: 'signed-field', text: 'challenge' }),
      document.createTextNode(' ‖ '),
      el('span', { class: 'signed-field highlight-origin', text: 'origin' }),
      document.createTextNode(' ‖ '),
      el('span', { class: 'signed-field', text: 'rpIdHash' }),
      document.createTextNode(' ‖ '),
      el('span', { class: 'signed-field', text: 'signCount' }),
      document.createTextNode(')'),
    ]),
    el('p', { class: 'ceremony-caption', text: 'The origin is part of the signed bytes — that is why a phishing site cannot forge a useful signature.' }),
  );

  // Arrow with label
  const arrow = el('div', { class: 'ceremony-arrow', 'aria-hidden': 'true' });
  arrow.append(
    el('span', { class: 'arrow-label', text: 'assertion (signature + signed bytes)' }),
    el('span', { class: 'arrow-shape', text: '➜' }),
  );

  // Server card
  const serverCard = el('div', { class: 'ceremony-actor ceremony-actor--server' });
  serverCard.append(
    el('div', { class: 'ceremony-actor-title' }, [
      el('span', { class: 'ceremony-actor-icon', 'aria-hidden': 'true', text: '🛡️' }),
      el('h3', { text: 'Relying Party server' }),
    ]),
    el('p', { class: 'ceremony-secret', text: 'public key only — no secret stored' }),
    el('ul', { class: 'ceremony-checks' }, [
      el('li', { text: 'verify ECDSA signature with stored public key' }),
      el('li', { text: 'challenge fresh? (anti-replay)' }),
      el('li', { text: 'origin matches expected? (anti-phishing)' }),
      el('li', { text: 'rpIdHash matches expected?' }),
      el('li', { text: 'signCount strictly increasing? (clone detection)' }),
    ]),
  );

  diagram.append(authCard, arrow, serverCard);
  section.append(diagram);
  return section;
}

// =====================================================================
// Register a passkey
// =====================================================================
function renderRegister(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'register', 'aria-labelledby': 'register-h' });

  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'register-h', text: 'Register a passkey' }),
      el('span', { class: 'section-kicker', text: 'Ceremony · step 1' }),
    ]),
    el('p', {
      text:
        'The authenticator generates a fresh ECDSA P-256 keypair bound to the relying party (example.com). It returns the public key — that is all the server keeps. The private key never leaves the authenticator.',
    }),
  );

  const out = el('div', {
    class: 'panel-card',
    id: 'register-out',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Registered credential output',
  });
  out.append(el('p', { class: 'mono', text: 'No credential yet. Click "Create passkey".' }));

  const button = el('button', { type: 'button', text: 'Create passkey' });
  button.addEventListener('click', () => {
    void (async () => {
      button.disabled = true;
      out.setAttribute('aria-busy', 'true');
      try {
        const cred = await state.auth.makeCredential(RP_ID);
        state.rp.register(cred);
        state.credential = cred;
        state.lastBaseline = null;
        renderCredential(out, cred);
        updateSignCountChip(state);
      } catch (err) {
        out.replaceChildren(
          el('p', { class: 'mono', text: `Error: ${(err as Error).message}` }),
        );
      } finally {
        out.removeAttribute('aria-busy');
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
    el('caption', { class: 'visually-hidden', text: 'Stored credential fields registered with the relying party' }),
    rowTH('Stored credential', 'value (truncated)'),
    row('Credential ID', shortB64(cred.credentialId, 22)),
    row('RP ID', cred.rpId),
    row('Public key (kty / crv)', `${kty} / ${crv}`),
    row('Public key x', x),
    row('Public key y', y),
    row('signCount', String(cred.signCount)),
  );
  container.append(
    el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Stored credential fields' }, [table]),
    el('p', {
      class: 'mono',
      text: 'The server stores all of this. It has no copy of the private key — there is no secret on the server to steal.',
    }),
  );
}

function rowTH(a: string, b: string): HTMLTableRowElement {
  const r = el('tr');
  r.append(el('th', { scope: 'col', text: a }), el('th', { scope: 'col', text: b }));
  return r;
}
function row(a: string, b: string): HTMLTableRowElement {
  const r = el('tr');
  r.append(el('th', { scope: 'row', text: a }), el('td', { class: 'mono', text: b }));
  return r;
}

// =====================================================================
// Authenticate
// =====================================================================
function renderLogin(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'login', 'aria-labelledby': 'login-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'login-h', text: 'Log in' }),
      el('span', { class: 'section-kicker', text: 'Ceremony · step 2' }),
    ]),
    el('p', {
      text:
        'The server issues a fresh challenge. The authenticator signs (challenge ‖ origin ‖ rpIdHash ‖ counter) with the private key. The server verifies the signature with the stored public key and checks every contextual field.',
    }),
  );

  const out = el('div', {
    class: 'panel-card',
    id: 'login-out',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Login verification result',
  });
  out.append(el('p', { class: 'mono', text: 'No login yet. Register first, then click "Authenticate".' }));

  const button = el('button', { type: 'button', text: 'Authenticate' });
  button.addEventListener('click', () => {
    void (async () => {
      if (!state.credential) {
        renderChecksError(out, 'Register a passkey first.');
        return;
      }
      button.disabled = true;
      out.setAttribute('aria-busy', 'true');
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
        const meta: VerifyMeta = { challenge, origin: ORIGIN_REAL, rpId: RP_ID };
        const result = await state.rp.verifyAssertion(assertionOrErr, {
          expectedChallenge: meta.challenge,
          expectedOrigin: meta.origin,
          expectedRpId: meta.rpId,
        });
        if (result.ok) {
          state.lastBaseline = { assertion: assertionOrErr, result, meta };
        }
        renderSingleResult(out, assertionOrErr, result, meta);
        updateSignCountChip(state);
      } catch (err) {
        renderChecksError(out, `Unexpected error: ${(err as Error).message}`);
      } finally {
        out.removeAttribute('aria-busy');
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

// =====================================================================
// Rendering verify results (single + side-by-side)
// =====================================================================
function renderSingleResult(
  container: HTMLElement,
  assertion: Assertion,
  result: VerifyResult,
  meta: VerifyMeta,
): void {
  container.replaceChildren(renderResultBlock(assertion, result, meta, false));
  if (meta.note) {
    container.append(el('p', { class: 'verify-note mono', text: meta.note }));
  }
}

function renderCompareResult(
  container: HTMLElement,
  baseline: BaselineSnapshot,
  attack: { assertion: Assertion; result: VerifyResult; meta: VerifyMeta },
): void {
  const grid = el('div', { class: 'compare-grid' });
  grid.append(
    el('div', { class: 'compare-col compare-col--baseline' }, [
      el('h4', { class: 'compare-col-title' }, [
        el('span', { class: 'compare-col-icon scenario-status scenario-status--valid', text: '✓' }),
        document.createTextNode('Baseline'),
      ]),
      renderResultBlock(baseline.assertion, baseline.result, baseline.meta, true),
    ]),
    el('div', { class: 'compare-col compare-col--attack' }, [
      el('h4', { class: 'compare-col-title' }, [
        el('span', {
          class: `compare-col-icon scenario-status ${attack.result.ok ? 'scenario-status--valid' : 'scenario-status--invalid'}`,
          text: attack.result.ok ? '✓' : '✗',
        }),
        document.createTextNode(attack.meta.label ?? 'Attack'),
      ]),
      renderResultBlock(attack.assertion, attack.result, attack.meta, true),
    ]),
  );
  container.replaceChildren(grid);
  if (attack.meta.note) {
    container.append(el('p', { class: 'verify-note mono', text: attack.meta.note }));
  }
}

function renderResultBlock(
  assertion: Assertion,
  result: VerifyResult,
  meta: VerifyMeta,
  compact: boolean,
): HTMLElement {
  const wrap = el('div', { class: 'result-block' });

  wrap.append(
    el('div', { class: 'verify-header' }, [
      el('span', {
        class: `scenario-status ${result.ok ? 'scenario-status--valid' : 'scenario-status--invalid'}`,
        text: result.ok ? 'Authenticated' : 'Rejected',
      }),
      el('span', { class: 'verify-summary', text: result.summary }),
    ]),
  );

  if (!compact) {
    const ctxBlock = el('table', { class: 'math-table' });
    ctxBlock.append(
      el('caption', { class: 'visually-hidden', text: 'Verifier context the server compared against the assertion' }),
      rowTH('Verifier context', 'value'),
      row('expectedChallenge', shortB64(meta.challenge, 22)),
      row('expectedOrigin', meta.origin),
      row('expectedRpId', meta.rpId),
    );
    wrap.append(el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Verifier context table' }, [ctxBlock]));
  }

  const list = el('ul', { class: 'check-list', 'aria-label': 'Per-check verification rows' });
  let spotlighted = false;
  for (const c of result.checks) {
    const isFirstFail = !c.pass && !spotlighted;
    if (isFirstFail) spotlighted = true;
    const li = el('li', {
      class: `check-row ${c.pass ? 'check-row--pass' : 'check-row--fail'}${isFirstFail ? ' check-row--fail-spotlight' : ''}`,
    });
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
  wrap.append(list);

  wrap.append(renderSignedBytesPanel(assertion, meta.origin));
  return wrap;
}

function renderSignedBytesPanel(assertion: Assertion, expectedOrigin: string): HTMLElement {
  const panel = el('div', { class: 'signed-bytes', 'aria-label': 'Real bytes the authenticator signed' });
  panel.append(
    el('p', { class: 'signed-bytes-title' }, [
      el('span', { class: 'signed-bytes-eyebrow', text: 'What the authenticator actually signed' }),
    ]),
  );

  // clientDataJSON with origin highlighted
  const clientDataDt = el('dt', { text: 'clientDataJSON' });
  const clientDataDd = el('dd');
  try {
    const obj = JSON.parse(assertion.clientDataJSON) as { type: string; challenge: string; origin: string };
    const originMatches = obj.origin === expectedOrigin;
    const originClass = originMatches ? 'highlight-origin highlight-origin--match' : 'highlight-origin highlight-origin--mismatch';
    clientDataDd.append(
      document.createTextNode(`{"type":"${obj.type}","challenge":"${shortB64(obj.challenge, 12)}","origin":"`),
      el('span', { class: originClass, text: obj.origin }),
      document.createTextNode('"}'),
    );
  } catch {
    clientDataDd.textContent = assertion.clientDataJSON;
  }

  const authDataDt = el('dt', { text: 'authData (rpIdHash | signCount)' });
  const authDataDd = el('dd', { class: 'mono', text: shortB64(assertion.authData, 60) });

  const sigDt = el('dt', { text: 'ECDSA signature (base64, truncated)' });
  const sigDd = el('dd', { class: 'mono', text: shortB64(assertion.signatureB64, 60) });

  const dl = el('dl', { class: 'signed-bytes-dl' });
  dl.append(clientDataDt, clientDataDd, authDataDt, authDataDd, sigDt, sigDd);
  panel.append(dl);

  panel.append(
    el('p', { class: 'signed-bytes-note', text: 'These are the real bytes. The signature ties them all together — change one character of clientDataJSON or one bit of the signature and ECDSA verification fails.' }),
  );
  return panel;
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
// Break it — four attack controls (now with side-by-side baseline)
// =====================================================================
function attackButton(label: string, emoji: string): HTMLButtonElement {
  const btn = el('button', { type: 'button', class: 'secondary' });
  btn.append(
    el('span', { class: 'emoji', 'aria-hidden': 'true', text: emoji }),
    document.createTextNode(label),
  );
  return btn;
}

function renderBreakIt(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'break-it', 'aria-labelledby': 'break-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'break-h', text: 'Break it (and watch each attack fail)' }),
      el('span', { class: 'section-kicker', text: 'The payoff' }),
    ]),
    el('p', {
      text:
        'Authenticate first to capture a baseline. Then run an attack — the baseline is held next to the result so you can see exactly which check changes.',
    }),
  );

  const out = el('div', {
    class: 'panel-card',
    id: 'attack-out',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Attack scenario result',
  });
  out.append(el('p', { class: 'mono', text: 'No attack run yet. Authenticate first, then pick a scenario.' }));

  const phishBtn = attackButton('Phishing site', '👻');
  const replayBtn = attackButton('Replay assertion', '🔁');
  const wrongRpBtn = attackButton('Wrong relying party', '🪤');
  const cloneBtn = attackButton('Cloned authenticator', '👯');
  const baselineBtn = attackButton('Reset baseline', '↺');

  phishBtn.addEventListener('click', () => void runPhishing(state, out, phishBtn));
  replayBtn.addEventListener('click', () => void runReplay(state, out, replayBtn));
  wrongRpBtn.addEventListener('click', () => void runWrongRp(state, out, wrongRpBtn));
  cloneBtn.addEventListener('click', () => void runClone(state, out, cloneBtn));
  baselineBtn.addEventListener('click', () => void runBaseline(state, out, baselineBtn));

  section.append(
    el('div', { class: 'playground-grid' }, [
      el('div', { class: 'panel-card attack-controls' }, [
        el('p', { text: 'Run an attack against the registered credential. Each restores cleanly so you can try the next.' }),
        el('div', { class: 'attack-button-row', role: 'group', 'aria-label': 'Attack scenarios' }, [
          phishBtn, replayBtn, wrongRpBtn, cloneBtn,
        ]),
        el('div', { class: 'attack-button-row' }, [baselineBtn]),
      ]),
      out,
    ]),
  );

  return section;
}

async function withBusy(out: HTMLElement, btn: HTMLButtonElement, fn: () => Promise<void>): Promise<void> {
  btn.disabled = true;
  out.setAttribute('aria-busy', 'true');
  try {
    await fn();
  } finally {
    out.removeAttribute('aria-busy');
    btn.disabled = false;
  }
}

function requireBaseline(state: DemoState, out: HTMLElement): BaselineSnapshot | null {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return null;
  }
  if (!state.lastBaseline) {
    renderChecksError(out, 'Click "Authenticate" first to capture a baseline. Each attack is shown alongside it.');
    return null;
  }
  return state.lastBaseline;
}

async function runPhishing(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  const baseline = requireBaseline(state, out);
  if (!baseline) return;
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      ORIGIN_PHISH,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      label: 'Phishing site',
      note: `Authenticator signed origin ${ORIGIN_PHISH}; verifier expected ${ORIGIN_REAL}. The look-alike domain cannot produce a usable assertion because the real origin is baked into what gets signed.`,
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
    });
    renderCompareResult(out, baseline, { assertion: assertionOrErr, result, meta });
    updateSignCountChip(state);
  });
}

async function runReplay(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  const baseline = requireBaseline(state, out);
  if (!baseline) return;
  await withBusy(out, btn, async () => {
    const challenge2 = randomChallenge();
    const replayed = await state.rp.verifyAssertion(baseline.assertion, {
      expectedChallenge: challenge2,
      expectedOrigin: ORIGIN_REAL,
      expectedRpId: RP_ID,
    });
    const meta: VerifyMeta = {
      challenge: challenge2,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      label: 'Replay attempt',
      note: 'The same assertion from the baseline is being replayed against a brand-new challenge. The signed challenge does not match the fresh one — replay blocked.',
    };
    renderCompareResult(out, baseline, { assertion: baseline.assertion, result: replayed, meta });
  });
}

async function runWrongRp(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  const baseline = requireBaseline(state, out);
  if (!baseline) return;
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      `https://${RP_ID_EVIL}`,
      RP_ID_EVIL,
    );
    if ('error' in assertionOrErr) {
      const refusedCol = el('div', { class: 'compare-col compare-col--attack' }, [
        el('h4', { class: 'compare-col-title' }, [
          el('span', { class: 'compare-col-icon scenario-status scenario-status--invalid', text: '✗' }),
          document.createTextNode('Wrong relying party'),
        ]),
        el('div', { class: 'verify-header' }, [
          el('span', { class: 'scenario-status scenario-status--invalid', text: 'Refused by authenticator' }),
          el('span', { class: 'verify-summary', text: assertionOrErr.error }),
        ]),
        el('p', {
          class: 'verify-note mono',
          text: `Credential is bound to ${RP_ID}; the authenticator will not produce an assertion for ${RP_ID_EVIL}. The verifier never even sees a signature.`,
        }),
      ]);
      const grid = el('div', { class: 'compare-grid' });
      grid.append(
        el('div', { class: 'compare-col compare-col--baseline' }, [
          el('h4', { class: 'compare-col-title' }, [
            el('span', { class: 'compare-col-icon scenario-status scenario-status--valid', text: '✓' }),
            document.createTextNode('Baseline'),
          ]),
          renderResultBlock(baseline.assertion, baseline.result, baseline.meta, true),
        ]),
        refusedCol,
      );
      out.replaceChildren(grid);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      label: 'Wrong relying party',
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
    });
    renderCompareResult(out, baseline, { assertion: assertionOrErr, result, meta });
  });
}

async function runClone(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  const baseline = requireBaseline(state, out);
  if (!baseline) return;
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const cloned: Assertion = { ...assertionOrErr, signCount: 0 };
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      label: 'Cloned authenticator',
      note: 'A clone of the authenticator would lag behind on the monotonic counter. The server sees signCount go backwards and flags it — clone detection.',
    };
    const result = await state.rp.verifyAssertion(cloned, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
    });
    renderCompareResult(out, baseline, { assertion: cloned, result, meta });
    updateSignCountChip(state);
  });
}

async function runBaseline(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: 'Baseline restored: a clean authentication against the real relying party with a fresh challenge.',
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
    });
    if (result.ok) {
      state.lastBaseline = { assertion: assertionOrErr, result, meta };
    }
    renderSingleResult(out, assertionOrErr, result, meta);
    updateSignCountChip(state);
  });
}

// =====================================================================
// Tamper interactive — the signature seals everything
// =====================================================================
function renderTamperPanel(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'tamper', 'aria-labelledby': 'tamper-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'tamper-h', text: 'Try tampering with a good assertion' }),
      el('span', { class: 'section-kicker', text: 'The signature seals everything' }),
    ]),
    el('p', {
      text:
        'Take the last successful baseline assertion and modify one field after the fact. Because the ECDSA signature was computed over the exact bytes, any change makes verification fail. This is what "the origin is signed" actually means.',
    }),
  );

  const out = el('div', {
    class: 'panel-card',
    id: 'tamper-out',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Tamper attempt result',
  });
  out.append(el('p', { class: 'mono', text: 'Authenticate first to capture a baseline, then try a tamper.' }));

  const flipSigBtn = attackButton('Flip 1 bit of signature', '🔧');
  const forgeOriginBtn = attackButton('Forge origin in clientDataJSON', '🎭');
  const bumpCounterBtn = attackButton('Bump signCount in authData', '🔢');

  flipSigBtn.addEventListener('click', () => void runTamper(state, out, flipSigBtn, 'flip-sig'));
  forgeOriginBtn.addEventListener('click', () => void runTamper(state, out, forgeOriginBtn, 'forge-origin'));
  bumpCounterBtn.addEventListener('click', () => void runTamper(state, out, bumpCounterBtn, 'bump-counter'));

  section.append(
    el('div', { class: 'playground-grid' }, [
      el('div', { class: 'panel-card attack-controls' }, [
        el('p', { text: 'Each button mutates one field of the baseline assertion. Watch the Signature check turn red.' }),
        el('div', { class: 'attack-button-row', role: 'group', 'aria-label': 'Tampering experiments' }, [
          flipSigBtn, forgeOriginBtn, bumpCounterBtn,
        ]),
      ]),
      out,
    ]),
  );

  return section;
}

type TamperKind = 'flip-sig' | 'forge-origin' | 'bump-counter';

function flipFirstBit(b64s: string): string {
  const bin = atob(b64s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  buf[0] ^= 0x01;
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s);
}

async function runTamper(state: DemoState, out: HTMLElement, btn: HTMLButtonElement, kind: TamperKind): Promise<void> {
  const baseline = requireBaseline(state, out);
  if (!baseline) return;
  await withBusy(out, btn, async () => {
    let tampered: Assertion = { ...baseline.assertion };
    let note = '';
    let label = '';

    if (kind === 'flip-sig') {
      tampered.signatureB64 = flipFirstBit(baseline.assertion.signatureB64);
      label = 'Signature: 1 bit flipped';
      note = 'Flipped one bit of the base64-decoded signature. ECDSA refuses to verify — even a single-bit change is detected. This is the "real crypto" property: the signature is not a checksum that ignores noise.';
    } else if (kind === 'forge-origin') {
      const client = JSON.parse(baseline.assertion.clientDataJSON) as { type: string; challenge: string; origin: string };
      client.origin = ORIGIN_PHISH;
      tampered.clientDataJSON = JSON.stringify(client);
      label = 'clientDataJSON: origin forged';
      note = `Rewrote the origin field in clientDataJSON to ${ORIGIN_PHISH} after the authenticator signed it. The Origin check fails AND the Signature check fails: the signed bytes contained the real origin's hash, so changing it invalidates both.`;
    } else {
      // bump-counter: modify authData (which is what's signed) to have a new count
      const parts = baseline.assertion.authData.split('|');
      const rpHash = parts[0] ?? '';
      const flags = parts[1] ?? '5'; // default UP|UV if missing
      tampered.authData = `${rpHash}|${flags}|999`;
      tampered.signCount = 999;
      label = 'authData: signCount bumped to 999';
      note = 'Bumped the signCount inside authData to 999. The Signature check fails because the bytes that were signed had the original (lower) count — the verifier recomputes over the new bytes and the signature does not match.';
    }

    const meta: VerifyMeta = {
      challenge: baseline.meta.challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      label,
      note,
    };
    const result = await state.rp.verifyAssertion(tampered, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
    });
    renderCompareResult(out, baseline, { assertion: tampered, result, meta });
  });
}

// =====================================================================
// Discoverable credentials + User Verification (Path B)
// =====================================================================
function flagsToText(f: number): string {
  const parts: string[] = [];
  parts.push((f & AUTH_FLAG_UP) ? 'UP' : '·');
  parts.push((f & AUTH_FLAG_UV) ? 'UV' : '·');
  return parts.join(' | ');
}

function renderDiscoverableUV(state: DemoState): HTMLElement {
  const section = el('section', { class: 'lab-section', id: 'discoverable', 'aria-labelledby': 'disc-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'disc-h', text: 'Discoverable credentials and User Verification' }),
      el('span', { class: 'section-kicker', text: 'What real WebAuthn adds (UP/UV flags)' }),
    ]),
    el('p', {
      text:
        'Real WebAuthn authData carries a flags byte. Two bits matter most: UP (User Present — the user touched the device) and UV (User Verified — they completed biometric or PIN). The simulator now models both, and discoverable lookup so the relying party never has to name a credential first. Three buttons below show the standard pass, an RP that demands UV, and what happens when UV was not performed.',
    }),
  );

  const out = el('div', {
    class: 'panel-card',
    id: 'discoverable-out',
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
    'aria-label': 'Discoverable-credential / UV result',
  });
  out.append(el('p', { class: 'mono', text: 'Register a passkey first. Then try the three buttons.' }));

  const discoverableBtn = attackButton('Discoverable login (UP+UV, RP requires UV)', '🪪');
  const demandUvFailBtn = attackButton('RP demands UV — authenticator only did UP', '⚠️');
  const noUpBtn = attackButton('RP demands UP — authenticator skipped UP', '🚫');

  discoverableBtn.addEventListener('click', () => void runDiscoverable(state, out, discoverableBtn));
  demandUvFailBtn.addEventListener('click', () => void runDemandUvFail(state, out, demandUvFailBtn));
  noUpBtn.addEventListener('click', () => void runDemandUpFail(state, out, noUpBtn));

  section.append(
    el('div', { class: 'playground-grid' }, [
      el('div', { class: 'panel-card attack-controls' }, [
        el('p', { text: 'These run against the same registered credential. The authenticator can be told to skip UP or UV; the verifier can be told to require them.' }),
        el('div', { class: 'attack-button-row', role: 'group', 'aria-label': 'Discoverable and UV scenarios' }, [
          discoverableBtn, demandUvFailBtn, noUpBtn,
        ]),
      ]),
      out,
    ]),
  );

  return section;
}

async function runDiscoverable(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    // Discoverable lookup: the authenticator picks a credential bound to rpId,
    // RP didn't pass a credentialId.
    const assertionOrErr = await state.auth.getAssertionByRpId(RP_ID, challenge, ORIGIN_REAL, {
      userPresent: true,
      userVerified: true,
    });
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: `Authenticator picked credential by rpId (no credentialId passed in). Flags asserted: ${flagsToText(assertionOrErr.flags)}. The RP also requires UV — both check rows now appear and both pass.`,
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
      requireUP: true,
      requireUV: true,
    });
    renderSingleResult(out, assertionOrErr, result, meta);
  });
}

async function runDemandUvFail(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
      { userPresent: true, userVerified: false }, // touch only, no biometric
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: `Authenticator asserted flags ${flagsToText(assertionOrErr.flags)} — UP set, UV NOT set. The relying party demands UV. The User-verified check fails: an attacker holding the device but lacking the biometric / PIN cannot log in.`,
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
      requireUP: true,
      requireUV: true,
    });
    renderSingleResult(out, assertionOrErr, result, meta);
  });
}

async function runDemandUpFail(state: DemoState, out: HTMLElement, btn: HTMLButtonElement): Promise<void> {
  if (!state.credential) {
    renderChecksError(out, 'Register a passkey first.');
    return;
  }
  await withBusy(out, btn, async () => {
    const challenge = randomChallenge();
    const assertionOrErr = await state.auth.getAssertion(
      state.credential!.credentialId,
      challenge,
      ORIGIN_REAL,
      RP_ID,
      { userPresent: false, userVerified: false },
    );
    if ('error' in assertionOrErr) {
      renderChecksError(out, assertionOrErr.error);
      return;
    }
    const meta: VerifyMeta = {
      challenge,
      origin: ORIGIN_REAL,
      rpId: RP_ID,
      note: `Authenticator asserted flags ${flagsToText(assertionOrErr.flags)} — UP NOT set (no user touch). The User-present check fails: even possession of the key without an explicit touch is rejected.`,
    };
    const result = await state.rp.verifyAssertion(assertionOrErr, {
      expectedChallenge: meta.challenge,
      expectedOrigin: meta.origin,
      expectedRpId: meta.rpId,
      requireUP: true,
      requireUV: false,
    });
    renderSingleResult(out, assertionOrErr, result, meta);
  });
}

// =====================================================================
// Why phishing fails / comparison
// =====================================================================
function renderPhishingExplainer(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'why-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'why-h', text: 'Why phishing fails' }),
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
      el('h2', { id: 'compare-h', text: 'Passwords vs passkeys' }),
      el('span', { class: 'section-kicker', text: 'At a glance' }),
    ]),
  );
  const table = el('table', { class: 'math-table', 'aria-labelledby': 'compare-h' });
  table.append(
    el('caption', { class: 'visually-hidden', text: 'Comparison of password and passkey properties' }),
  );
  const head = el('tr');
  head.append(
    el('th', { scope: 'col', text: 'Property' }),
    el('th', { scope: 'col', text: 'Password' }),
    el('th', { scope: 'col', text: 'Passkey' }),
  );
  table.append(head);
  for (const r of PASSWORD_VS_PASSKEY) {
    const tr = el('tr');
    tr.append(
      el('th', { scope: 'row', text: r.property }),
      el('td', { text: r.password }),
      el('td', { text: r.passkey }),
    );
    table.append(tr);
  }
  section.append(el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Password vs passkey comparison' }, [table]));

  return section;
}

function renderCeremonyTable(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'ceremony-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'ceremony-h', text: 'The ceremony at a glance' }),
      el('span', { class: 'section-kicker', text: 'Step by step' }),
    ]),
    el('p', {
      text: 'Every step that touches a secret happens inside the authenticator. The server only ever sees public material.',
    }),
  );
  const table = el('table', { class: 'math-table', 'aria-labelledby': 'ceremony-h' });
  table.append(
    el('caption', { class: 'visually-hidden', text: 'Six-step registration and authentication ceremony' }),
  );
  const head = el('tr');
  head.append(
    el('th', { scope: 'col', text: 'Phase' }),
    el('th', { scope: 'col', text: '#' }),
    el('th', { scope: 'col', text: 'Actor' }),
    el('th', { scope: 'col', text: 'What happens' }),
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
  section.append(el('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Ceremony steps' }, [table]));
  return section;
}

// =====================================================================
// In the real world
// =====================================================================
function renderRealWorld(): HTMLElement {
  const section = el('section', { class: 'lab-section', 'aria-labelledby': 'real-h' });
  section.append(
    el('div', { class: 'section-heading-row' }, [
      el('h2', { id: 'real-h', text: 'In the real world' }),
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
  const footer = el('footer', { class: 'scripture-footer', role: 'contentinfo' });
  footer.append(
    el('p', { text: SCRIPTURE_TEXT }),
    el('cite', { text: `— ${SCRIPTURE_CITATION}` }),
  );
  return footer;
}
