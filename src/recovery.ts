/** Fictional account policy, not a model of any specific provider's controls. */
export interface RecoveryState {
  attackerPasskey: boolean;
  attackerSession: boolean;
  attackerRecovery: boolean;
  attackerPassword: boolean;
  evidenceSaved: boolean;
  evidenceRoutes?: string[];
}
export type RecoveryAction = 'record' | 'revoke' | 'logout' | 'secure-recovery' | 'reset-password' | 'try-access';
export const initialRecovery = (): RecoveryState => ({
  attackerPasskey: true, attackerSession: true, attackerRecovery: true,
  attackerPassword: true, evidenceSaved: false,
});
export function accessRoutes(s: RecoveryState): string[] {
  return [s.attackerPasskey && 'unrecognized passkey', s.attackerSession && 'existing session',
    s.attackerRecovery && 'recovery email', s.attackerPassword && 'known password'].filter((v): v is string => Boolean(v));
}
export function recover(s: RecoveryState, action: RecoveryAction): RecoveryState {
  const next = { ...s };
  if (action === 'record' && !s.evidenceSaved) { next.evidenceSaved = true; next.evidenceRoutes = accessRoutes(s); }
  if (action === 'revoke') next.attackerPasskey = false;
  if (action === 'logout') next.attackerSession = false;
  if (action === 'secure-recovery') next.attackerRecovery = false;
  if (action === 'reset-password') next.attackerPassword = false;
  if (action === 'try-access' && accessRoutes(s).length > 0) next.attackerSession = true;
  return next;
}

export function renderRecovery(): HTMLElement {
  let state = initialRecovery();
  const section = document.createElement('section');
  section.className = 'lab-section';
  section.id = 'account-recovery';
  section.setAttribute('aria-labelledby', 'recovery-h');
  section.innerHTML = `
    <h2 id="recovery-h">Account recovery is more than a successful login</h2>
    <p>Synthetic exercise: an intruder enrolled a passkey, kept a session, added a recovery email, and learned the password. You still control one trusted passkey. Predict which access routes each action closes, then test your prediction.</p>
    <p>This fictional policy keeps credentials, sessions, passwords, and recovery routes independent. No real account, credential, or browser passkey is changed. Provider behavior varies; this is not a provider-specific recovery checklist.</p>
    <div class="panel-card">
      <h3>Account inventory</h3>
      <p>Your trusted passkey stays enrolled. The unrecognized passkey, intruder session, recovery email, and exposed password are separate entries. Names alone do not establish who owns a real passkey.</p>
      <ul id="recovery-inventory"></ul>
      <div id="recovery-actions"></div>
      <p id="recovery-result" role="status" aria-live="polite"></p>
    </div>
    <p>Try resetting the password alone, then logging out all sessions. Can the intruder return? Close every remaining route and retry. Explain why authentication proves control of a credential but does not prove the account has been remediated.</p>
    <p>Source: <a href="https://www.usenix.org/conference/usenixsecurity26/presentation/daffalla">Daffalla et al., “Maybe there’s only one passkey?”</a>, a qualitative study with 31 participants using Google, PayPal, and LinkedIn tasks. It motivates separating investigation from remediation; it does not establish universal failure rates or current provider behavior.</p>`;
  const result = section.querySelector<HTMLElement>('#recovery-result')!;
  const render = (action?: RecoveryAction) => {
    const inventory = section.querySelector('#recovery-inventory')!;
    inventory.replaceChildren();
    for (const [label, active] of [
      ['Unrecognized passkey enrolled', state.attackerPasskey], ['Intruder session active', state.attackerSession],
      ['Intruder recovery email enabled', state.attackerRecovery], ['Exposed password accepted', state.attackerPassword],
      ['Fictional inventory snapshot recorded', state.evidenceSaved],
    ] as const) {
      const li = document.createElement('li'); li.textContent = `${label}: ${active ? 'yes' : 'no'}`; inventory.append(li);
    }
    const routes = accessRoutes(state);
    result.textContent = `${action === 'try-access' ? (routes.length ? 'Intruder has a session again. ' : 'Intruder cannot re-enter in this model. ') : ''}${routes.length ? `Remaining access: ${routes.join(', ')}.` : 'All modeled intruder access routes are closed; your trusted passkey remains available.'} ${state.evidenceSaved ? `Recorded routes (preserved): ${state.evidenceRoutes?.join(', ') || 'none'}.` : 'Inventory has not been recorded.'}`;
  };
  const controls = section.querySelector('#recovery-actions')!;
  for (const [action, label] of [
    ['record', 'Record inventory snapshot'], ['revoke', 'Revoke unrecognized passkey'], ['logout', 'Log out all sessions'],
    ['secure-recovery', 'Remove intruder recovery email'], ['reset-password', 'Reset password'], ['try-access', 'Try intruder access'],
  ] as const) {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'btn'; button.textContent = label;
    button.addEventListener('click', () => { state = recover(state, action); render(action); }); controls.append(button);
  }
  const reset = document.createElement('button'); reset.type = 'button'; reset.className = 'btn'; reset.textContent = 'Reset fictional account';
  reset.addEventListener('click', () => { state = initialRecovery(); render(); }); controls.append(reset);
  render();
  return section;
}
