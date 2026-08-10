import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** The two viewports the gate runs at: desktop, and phone width for WCAG 1.4.10. */
export const WIDE = { width: 1280, height: 900 };
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Four rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     pushed `*{…opacity:1!important}` through `addStyleTag`, which is not a
 *     neutral convenience on this page — `.cl-hero-sub` renders at
 *     `opacity: .85` and every disabled button at `.5`. Forcing those opaque
 *     handed axe foreground colours the page never paints, so a green contrast
 *     result meant nothing. It also ran a `revealAll()` that set `.open` on
 *     every `<details>` and stripped `[hidden]` from every element at once,
 *     producing a document no visitor can load.
 *
 *  2. IT DROVE THE WHOLE LAB AND SCANNED ONCE, AT THE END. That is a distinct
 *     failure from never driving at all, and it is worth naming: the old drive
 *     clicked register, authenticate, four attacks, three tampers and three
 *     discoverable scenarios — and then handed axe the single final frame. Each
 *     of those clicks REPLACES `#attack-out` / `#tamper-out` / `#discoverable-out`
 *     wholesale, so eleven renderings were constructed and thrown away
 *     unmeasured. This gate scans after every single step.
 *
 *  3. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. axe over a placeholder passes having checked nothing. At
 *     first paint every output panel on this page holds one grey `<p class="mono">`
 *     of instructions: no credential table, no check rows, no pass/fail badges,
 *     no signed-bytes panel, no compare grid. The `.check-row--fail` /
 *     `.scenario-status--invalid` / `.highlight-origin--mismatch` renderings —
 *     which are the entire point of a lab about attacks that fail — exist
 *     nowhere until an attack is run.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block collapses `animation-duration` and `transition-duration`
 * to 0.001s rather than setting `animation: none`, which is the safe form — a
 * cancelled animation loses its end state, a zero-length one still lands on it.
 * That block declares nothing but durations, an iteration count and the theme
 * toggle's `transform`, so it cannot itself introduce a contrast defect.
 *
 * `aria-hidden` subtrees are excluded. The cost of that exclusion is stated
 * plainly: text removed from the accessibility tree AND painted at zero opacity
 * is not checked here — which is why `expectNoLiveTextAriaHidden` exists.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * `aria-hidden` must cover decoration only, never words.
 *
 * Both oracles this gate runs skip `aria-hidden` text — axe's `color-contrast`
 * rule by design, and `auditContrast` deliberately, to match it. That shared
 * blind spot means a single misplaced `aria-hidden` removes a region from the
 * accessibility tree AND from every contrast measurement at once, and both
 * halves of the gate go green on content nobody can read either way.
 *
 * The rule enforced here is narrow enough to be objective: a hidden subtree may
 * hold glyphs (emoji, arrows, check marks — marks that carry no meaning a
 * screen-reader user is missing), but not letters or digits. That is exactly
 * the boundary this lab's markup crosses in one place and honours in the
 * others: the 🔐/🛡️ actor icons and the attack buttons' emoji are marks beside
 * a visible label, but the ceremony arrow's caption is a sentence.
 */
export async function expectNoLiveTextAriaHidden(page: Page, label: string): Promise<void> {
  const hidden = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('[aria-hidden="true"]'))) {
      // Only the outermost hidden ancestor matters; nested ones repeat it.
      if (el.parentElement?.closest('[aria-hidden="true"]')) continue;
      const text = (el.textContent ?? '').trim();
      if (!/[A-Za-z0-9]/.test(text)) continue;
      out.push(
        `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}` +
          `${el.getAttribute('class') ? '.' + el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` — "${text.slice(0, 60)}"`
      );
    }
    return out;
  });
  expect(
    Array.from(new Set(hidden)),
    `aria-hidden may cover glyphs, not words, in state: ${label}`
  ).toEqual([]);
}

/**
 * Load the page in a known theme and viewport with reduced motion actually in
 * effect, and assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page: an emulation that silently did nothing would
 * leave the gate certifying a different rendering than the one it claims to.
 *
 * The theme is seeded through `localStorage` under the key `index.html`'s
 * anti-flash script reads — `crypto-lab-theme` — so the requested theme is on
 * the first painted frame rather than being toggled in afterwards.
 */
export async function boot(
  page: Page,
  theme: 'dark' | 'light',
  viewport: { width: number; height: number }
): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.setViewportSize(viewport);
  await page.emulateMedia({ reducedMotion: 'reduce', colorScheme: theme });
  await page.addInitScript((t) => localStorage.setItem('crypto-lab-theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The whole page is built by `src/ui.ts` into an empty `#app`, so a
  // navigation that resolves proves nothing.
  for (const id of ['register', 'login', 'break-it', 'tamper', 'discoverable', 'live-demo']) {
    await expect(page.locator(`#${id}`)).toBeVisible();
  }
  // Every output region genuinely holds nothing but a placeholder here, which is
  // the whole reason `driveAllStates` exists.
  await expect(page.locator('#register-out')).toContainText('No credential yet');
  await expect(page.locator('#login-out')).toContainText('No login yet');
  await expect(page.locator('#attack-out')).toContainText('No attack run yet');
  await expect(page.locator('#tamper-out')).toContainText('Authenticate first');
  await expect(page.locator('#discoverable-out')).toContainText('Register a passkey first');
  await expect(page.locator('.check-row')).toHaveCount(0);
  await expect(page.locator('.compare-grid')).toHaveCount(0);
  await expect(page.locator('.scenario-status')).toHaveCount(0);

  // `live.ts` is mounted asynchronously after `mountApp`, so the live panel is
  // still the "Loading the live-demo module…" placeholder for a moment.
  await expect(page.locator('#live-out')).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender at 380px: it lays out four `min-width: 320px` tables, a
 * two-column baseline-vs-attack compare grid, and check rows built from a
 * fixed-track CSS grid whose columns are declared in pixels.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That
    // cost a run elsewhere in this fleet, and this lab has the same decoy:
    // every `.math-table` is 320px minimum inside its own `.table-wrap`
    // scroller.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll. Live here: the four `.table-wrap`
 * scrollers, which really do scroll at 380px.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Six assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here, since every status pill on the
 *    page is a translucent tint axe declines to resolve. Everything else in that
 *    bucket is a real result axe simply could not finish — including
 *    `aria-prohibited-attr`, which is where an `aria-label` on a role-less div
 *    hides, a defect that never reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - `aria-hidden` covering words rather than glyphs — the one gap both
 *    contrast oracles share.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoLiveTextAriaHidden(page, label);
  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/**
 * A Chromium virtual authenticator, driven over CDP.
 *
 * The bottom section of this lab is not a simulation: it calls
 * `navigator.credentials.create` / `.get` for real. Under Playwright there is
 * no passkey provider behind those calls, so without help the whole Path C
 * panel is unreachable — which is precisely the situation the old gate was in,
 * and precisely why it never measured a single one of the live registration and
 * assertion renderings. Chromium's `WebAuthn` CDP domain supplies a real
 * authenticator implementation that satisfies the same API, so the states are
 * reached by the same clicks a visitor makes rather than faked.
 *
 * `transport: 'internal'` plus `hasUserVerification`/`isUserVerified` is what
 * makes `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
 * resolve true, which is the branch that paints `.live-status--available`. The
 * gate scans the OTHER branch too, before the authenticator is added — see
 * `driveAllStates`.
 */
export async function addVirtualAuthenticator(page: Page): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE REJECTED ASSERTION IS THE CLAIM. A passkey is only interesting because
 *    the relying party refuses a signature made for the wrong origin, an old
 *    challenge, or a rolled-back counter. `.check-row--fail`,
 *    `.check-row--fail-spotlight`, `.scenario-status--invalid` and
 *    `.highlight-origin--mismatch` exist nowhere until an attack is run, and
 *    each of the four attacks, the three tampers and the two UP/UV refusals
 *    replaces the output panel wholesale — so each is scanned on its own frame.
 *
 *  - THE PREREQUISITE STATES COME BEFORE THE UNLOCK, NOT AFTER. Every action on
 *    this page is gated: attacks need a baseline, a baseline needs a login, a
 *    login needs a credential. `renderChecksError` — a bare "Rejected" badge
 *    with an instruction and no check list — is what a visitor sees if they
 *    press the buttons in the order they appear on screen, and it is only
 *    reachable before the prerequisite is met. So the gate presses them in that
 *    order first, from the top of the page down, exactly as a first-time
 *    visitor would.
 *
 *  - BOTH LIVE-DEMO CAPABILITY BRANCHES ARE REAL STATES. `.live-status--available`
 *    and `.live-status--unavailable` are painted from a capability probe that
 *    runs once at mount, so no click reaches the other one. The gate loads the
 *    page twice: once with no authenticator attached (the "no platform
 *    authenticator" rendering a desktop visitor without Touch ID / Windows
 *    Hello actually gets) and once with one (the available rendering, and the
 *    real registration and assertion panels behind it).
 *
 *  - EVERY WAIT IS ON A COMPLETION SIGNAL. Each handler disables its button,
 *    sets `aria-busy` on the output, awaits Web Crypto, then re-renders — so
 *    each step is awaited on the rendered result appearing, never on a timeout.
 *
 *  - ONE STATE IS GENUINELY UNREACHABLE AND IS NOT FAKED. `renderLiveError`
 *    paints when the real ceremony throws — a user cancelling the platform
 *    prompt, or an authenticator that refuses. CDP's virtual authenticator has
 *    no cancel signal; the only way to make `navigator.credentials.get` reject
 *    is to let its 60s timeout expire, which would hang the gate for a minute
 *    per configuration to measure a `<p class="mono">` identical in class and
 *    container to the placeholder already scanned at first paint. It is left
 *    undriven deliberately, and recorded here rather than papered over.
 */
export async function driveAllStates(page: Page, theme: string, size: string): Promise<void> {
  const at = (s: string): string => `${theme} ${size} / ${s}`;

  // ── Phase 1: no authenticator attached ───────────────────────────────────
  await scan(page, at('first paint'));

  // Both skip links park off-screen until focused; the focused rendering is the
  // only one that paints, and it is the first thing a keyboard user meets.
  await page.locator('a.cl-skip-link').focus();
  await scan(page, at('shared-header skip link focused'));
  await page.locator('a.skip-link').focus();
  await scan(page, at('lab skip link focused'));

  // The live panel's capability probe found no platform authenticator here.
  await expect(page.locator('#live-demo-host .live-status--unavailable')).toContainText(
    'No platform authenticator'
  );
  await scan(page, at('live demo: no platform authenticator'));

  // ── The locked states, pressed in the order they appear on the page ──────
  await page.locator('#login').getByRole('button', { name: 'Authenticate' }).click();
  await expect(page.locator('#login-out')).toContainText('Register a passkey first');
  await scan(page, at('login refused: no credential yet'));

  await page.locator('#break-it').getByRole('button', { name: 'Phishing site' }).click();
  await expect(page.locator('#attack-out')).toContainText('Register a passkey first');
  await scan(page, at('attack refused: no credential yet'));

  await page.locator('#tamper').getByRole('button', { name: 'Flip 1 bit of signature' }).click();
  await expect(page.locator('#tamper-out')).toContainText('Register a passkey first');
  await scan(page, at('tamper refused: no credential yet'));

  await page
    .locator('#discoverable')
    .getByRole('button', { name: 'Discoverable login' })
    .click();
  await expect(page.locator('#discoverable-out')).toContainText('Register a passkey first');
  await scan(page, at('discoverable refused: no credential yet'));

  // ── Phase 2: a real authenticator is attached, and the page reloaded ─────
  await addVirtualAuthenticator(page);
  await page.reload();
  await expect(page.locator('#live-demo-host .live-status--available').nth(1)).toContainText(
    'Platform authenticator with user verification is available'
  );
  await expect(page.locator('#register-out')).toContainText('No credential yet');
  await settle(page);
  await scan(page, at('live demo: platform authenticator available'));

  // ── Register: the credential table, and the signCount chip's first paint ─
  await page.locator('#register').getByRole('button', { name: 'Create passkey' }).click();
  await expect(page.locator('#register-out table')).toBeVisible();
  await expect(page.locator('#register-out')).toContainText('P-256');
  await scan(page, at('passkey registered'));

  // Registered, but no baseline yet — a second, differently-worded locked state.
  await page.locator('#break-it').getByRole('button', { name: 'Replay assertion' }).click();
  await expect(page.locator('#attack-out')).toContainText('capture a baseline');
  await scan(page, at('attack refused: no baseline yet'));

  // ── Authenticate: the accepted assertion, all five checks green ──────────
  await page.locator('#login').getByRole('button', { name: 'Authenticate' }).click();
  await expect(
    page.locator('#login-out .verify-header .scenario-status--valid')
  ).toContainText('Authenticated');
  await expect(page.locator('#login-out .check-row--pass').first()).toBeVisible();
  await expect(page.locator('#login-out .highlight-origin--match')).toBeVisible();
  await scan(page, at('authenticated: assertion accepted'));

  // ── The four attacks, each its own compare-grid rendering ────────────────
  for (const [button, expected] of [
    ['Phishing site', 'examp1e-login.com'],
    ['Replay assertion', 'replayed against a brand-new challenge'],
    ['Wrong relying party', 'Refused by authenticator'],
    ['Cloned authenticator', 'clone detection'],
  ] as const) {
    await page.locator('#break-it').getByRole('button', { name: button }).click();
    await expect(page.locator('#attack-out .compare-grid')).toBeVisible();
    await expect(page.locator('#attack-out')).toContainText(expected);
    await expect(page.locator('#attack-out .scenario-status--invalid').first()).toBeVisible();
    await scan(page, at(`attack: ${button}`));
  }

  // The Reset control, which restores a clean single-column accepted result.
  await page.locator('#break-it').getByRole('button', { name: 'Reset baseline' }).click();
  await expect(page.locator('#attack-out')).toContainText('Baseline restored');
  await expect(page.locator('#attack-out .compare-grid')).toHaveCount(0);
  await scan(page, at('attack: baseline reset'));

  // ── The three tampers: the signature seal, each rendering separately ─────
  for (const [button, expected] of [
    ['Flip 1 bit of signature', 'Signature: 1 bit flipped'],
    ['Forge origin in clientDataJSON', 'origin forged'],
    ['Bump signCount in authData', 'signCount bumped to 999'],
  ] as const) {
    await page.locator('#tamper').getByRole('button', { name: button }).click();
    await expect(page.locator('#tamper-out .compare-grid')).toBeVisible();
    await expect(page.locator('#tamper-out')).toContainText(expected);
    await expect(page.locator('#tamper-out .check-row--fail-spotlight')).toBeVisible();
    await scan(page, at(`tamper: ${button}`));
  }

  // ── Discoverable / UP / UV: one accepted, two refused ────────────────────
  await page.locator('#discoverable').getByRole('button', { name: 'Discoverable login' }).click();
  await expect(
    page.locator('#discoverable-out .verify-header .scenario-status--valid')
  ).toContainText('Authenticated');
  await expect(page.locator('#discoverable-out')).toContainText('UP | UV');
  await scan(page, at('discoverable login accepted (UP+UV)'));

  for (const [button, expected] of [
    ['RP demands UV', 'UV NOT set'],
    ['RP demands UP', 'UP NOT set'],
  ] as const) {
    await page.locator('#discoverable').getByRole('button', { name: button }).click();
    await expect(
      page.locator('#discoverable-out .verify-header .scenario-status--invalid')
    ).toContainText('Rejected');
    await expect(page.locator('#discoverable-out')).toContainText(expected);
    await scan(page, at(`discoverable: ${button}`));
  }

  // ── Path C: the real browser ceremony, against the virtual authenticator ─
  await page.getByRole('button', { name: 'Register a real passkey' }).click();
  await expect(page.locator('#live-out')).toContainText('Registration response');
  await expect(page.locator('#live-out .live-flag--on').first()).toBeVisible();
  await expect(page.locator('#live-out .live-flag--off').first()).toBeVisible();
  await scan(page, at('live demo: real passkey registered'));

  await page.getByRole('button', { name: 'Authenticate with the real passkey' }).click();
  await expect(page.locator('#live-out .verify-header')).toContainText('Verified');
  await expect(page.locator('#live-out')).toContainText('Real assertion (verified locally)');
  await scan(page, at('live demo: real assertion verified'));
}
