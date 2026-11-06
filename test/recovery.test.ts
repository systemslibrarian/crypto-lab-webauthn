import { describe, it, expect } from 'vitest';
import { accessRoutes, initialRecovery, recover } from '../src/recovery';
describe('fictional recovery routes', () => {
  it('password reset does not remove passkeys, sessions or recovery routes', () => {
    expect(accessRoutes(recover(initialRecovery(), 'reset-password'))).toEqual(['unrecognized passkey', 'existing session', 'recovery email']);
  });
  it('revoking a passkey does not close an existing session', () => {
    expect(recover(initialRecovery(), 'revoke').attackerSession).toBe(true);
  });
  it('logout permits re-entry through any remaining route', () => {
    for (const key of ['attackerPasskey', 'attackerRecovery', 'attackerPassword'] as const) {
      const s = { attackerPasskey: false, attackerSession: false, attackerRecovery: false, attackerPassword: false, evidenceSaved: false, [key]: true };
      expect(recover(s, 'try-access').attackerSession).toBe(true);
    }
  });
  it('closing all routes prevents re-entry, with no evidence action required for access control', () => {
    let s = initialRecovery();
    for (const a of ['revoke', 'secure-recovery', 'reset-password', 'logout'] as const) s = recover(s, a);
    expect(accessRoutes(recover(s, 'try-access'))).toEqual([]);
    expect(s.evidenceSaved).toBe(false);
  });
  it('recording evidence changes no access routes and transitions do not mutate input', () => {
    const s = initialRecovery(); const next = recover(s, 'record');
    expect(accessRoutes(next)).toEqual(accessRoutes(s)); expect(s.evidenceSaved).toBe(false);
  });
});
