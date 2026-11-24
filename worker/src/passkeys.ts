import { DurableObject } from 'cloudflare:workers';
import { createHostApprovalKey, signHostApproval } from './host-approval';
import hostApprovalGate from '../../experiments/tailnet/host-approval.py';
import { classify } from './classify';
import { assessScope, scopeUnavailable, type DecisionModel } from './assessment';
import { createHash, createHmac, randomInt, timingSafeEqual } from 'node:crypto';
import {
  generateAuthenticationOptions, generateRegistrationOptions,
  verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type RegistrationResponseJSON, type WebAuthnCredential,
} from '@simplewebauthn/server';
import browserBundle from './passkey-browser.txt';
import approvalPage from './passkey-page.html';
import approvalStyles from './passkey-page.css';
import pairingInstaller from './pairing-install.sh';
import pairingDetector from './pairing-detect.sh';
import { sameEnrollmentHost, isHostAccount, enrollmentMarker, restartUnit, validEnrollmentHost, validTailnetIpv4, legacyAccount, maintenanceAccount, type HostAccount, type Host, type TailnetDevice } from '../../experiments/tailnet/credentials';

const lifetime = 5 * 60_000;
const approvalLifetime = 15 * 60_000;
const prefix = '/passkeys';
const empty = { executed: false };
const diagnostic = { host: 'ams', operation: 'openbot-enrollment-check-v1', execution_identity: maintenanceAccount, dry_run: true } as const;
const hostCheck = { ...diagnostic, operation: 'run openbot-enrollment-check-v1 to verify SSH enrollment', dry_run: false } as const;
const commandCheck = 'echo ' + enrollmentMarker;
const commandRestart = '/usr/bin/sudo -n -- /usr/bin/systemctl restart ' + restartUnit;
const restartOperation = 'restart ' + restartUnit;
const commandOperation = 'run approved Bash command';
const isHostOperation = (operation: string) => operation === hostCheck.operation || operation === restartOperation || operation === commandOperation;
type HostVerification = 'unconfigured' | 'target_changed' | 'host_key_unverified' | 'ssh_authentication_failed' | 'verified' | 'connection_failed';
type HostResult =
  | { state: 'command_completed' | 'command_failed'; executed: true; stdout: string; stderr: string; exit_status: number; truncated: boolean }
  | { state: 'verified' | 'service_restarted'; executed: true; stdout: string; exit_status: 0 }
  | { state: 'unconfigured' | 'target_changed' | 'host_key_unverified' | 'ssh_authentication_failed'; executed: false }
  | { state: 'diagnostic_failed' | 'restart_failed' | 'check_outcome_unknown'; executed: null; exit_status?: number | null };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
type Job = {
  target: typeof diagnostic | (Omit<typeof hostCheck, 'host' | 'operation' | 'execution_identity'> & { host: string; fingerprint: string; enrollmentId?: string; commandExecution?: boolean; signedApproval?: boolean; operation: string; execution_identity: HostAccount });
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  expires_at: number;
  command?: string;
  statement?: string;
  hostName?: string;
  scope?: string;
  approved_at?: number;
  execution_owner?: string;
  retry_lock?: string;
  reconciled_at?: number;
  host_verification?: HostVerification;
  host_result?: HostResult;
};
type Enrollment = { challenge: string; expires: number };
type PairingProgress = { state: string; host?: string; failure?: string };
type Pairing = { commandExecution?: boolean; signedApproval?: boolean; automatic?: boolean; check?: HostResult; addressName?: string; probeAddress?: string; receiptHash?: string; id: string; address: string; tokenHash: string; expires: number; fingerprint?: string; reviewJobId?: string; account?: HostAccount; accountAction?: 'created' | 'reused' | 'existing' | 'canceled' };
const reviewRetention = 24 * 60 * 60_000;
const retentionScanInterval = 60 * 60_000;
const pairingLifetime = 15 * 60_000;
const pairingIdLength = 8;
const pairingTokenLength = 10;
const pairingAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const validPairingId = (id: string) => /^[A-Za-z0-9]{8}$/u.test(id) || uuid.test(id);
const validPairingToken = (token: string) => /^(?:[A-Za-z0-9]{10}|[0-9a-f-]{72})$/u.test(token);

function randomPairingCode(length: number) {
  return Array.from({ length }, () => pairingAlphabet[randomInt(pairingAlphabet.length)]).join('');
}
const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
export type PasskeyEnv = {
  PASSKEYS: DurableObjectNamespace<PasskeyApproval>;
  AI?: DecisionModel;
  PASSKEY_ORIGIN?: string;
  PASSKEY_SETUP_TOKEN?: string;
  PASSKEY_LOCAL_TEST_JOB_TTL_MS?: string;
  HOST_PROBE?: {
    runHostEnrollmentCheck(expected: Host): Promise<HostResult>;
    runApprovedCommand(expected: Host, command: string): Promise<HostResult>;
    restartDemoService(expected: Host): Promise<HostResult>;
    prepareEnrollment(): Promise<{ state: string; installCommand?: string; deviceTag?: string; devices?: TailnetDevice[]; probeAddress?: string; loginUrl?: string; needsDeviceApproval?: boolean }>;
    startDeviceLogin(): Promise<boolean>;
    removeEnrollmentHost(expected: Host): Promise<boolean>;
    prepareHostKey(address: string, account: HostAccount, commandExecution?: boolean): Promise<string | null>;
    configureTailnet(clientId: string, clientSecret: string): Promise<boolean>;
    saveEnrollmentHost(host: Host): Promise<boolean>;
  };
};

export function passkeyOrigin(env: PasskeyEnv) {
  try {
    const url = new URL(env.PASSKEY_ORIGIN ?? '');
    if (url.origin === env.PASSKEY_ORIGIN &&
        (url.protocol === 'https:' || url.origin === 'http://localhost:8795')) return url;
  } catch { /* disabled without a valid origin */ }
}

function setupAuthorized(env: PasskeyEnv, token: unknown) {
  if (!env.PASSKEY_SETUP_TOKEN || env.PASSKEY_SETUP_TOKEN.length < 32 || typeof token !== 'string') return false;
  const hash = (value: string) => createHash('sha256').update(value).digest();
  return timingSafeEqual(hash(token), hash(env.PASSKEY_SETUP_TOKEN));
}

export class PasskeyApproval extends DurableObject<PasskeyEnv> {
  #executionOwner = crypto.randomUUID();
  #changingHosts = new Set<string>();
  #finishingPairings = new Map<string, Promise<PairingProgress | null>>();

  #credential() { return this.ctx.storage.get<WebAuthnCredential>('credential'); }

  #jobLifetime() {
    const testLifetime = Number(this.env.PASSKEY_LOCAL_TEST_JOB_TTL_MS);
    return passkeyOrigin(this.env)?.protocol === 'http:' &&
      Number.isSafeInteger(testLifetime) && testLifetime > 0 && testLifetime < approvalLifetime ? testLifetime : approvalLifetime;
  }

  async #ownerAuthorized(token: unknown) {
    if (typeof token !== 'string' || !/^[0-9a-f-]{72}$/u.test(token)) return false;
    const session = await this.ctx.storage.get<{ hash: string; expires: number }>('owner-session');
    return Boolean(session && session.expires > Date.now() &&
      timingSafeEqual(Buffer.from(session.hash), Buffer.from(hashToken(token))));
  }

  async authorizeReview(token: unknown) {
    return this.#ownerAuthorized(token);
  }

  async ownerState() {
    return {
      enrolled: Boolean(await this.#credential()),
      pairingIdLength,
      pairingTokenLength,
    };
  }

  async #signInSeal(payload: string) {
    let key = await this.ctx.storage.get<string>('owner-sign-in-key');
    if (!key) {
      const candidate = crypto.randomUUID() + crypto.randomUUID();
      key = await this.ctx.storage.transaction(async tx => {
        const existing = await tx.get<string>('owner-sign-in-key');
        if (existing) return existing;
        await tx.put('owner-sign-in-key', candidate);
        return candidate;
      });
    }
    return createHmac('sha256', key).update(payload).digest('hex');
  }

  async signInOptions() {
    if (!await this.#credential()) return null;
    const origin = passkeyOrigin(this.env)!;
    const options = await generateAuthenticationOptions({ rpID: origin.hostname, userVerification: 'required' });
    const payload = (Date.now() + lifetime) + '.' + options.challenge;
    return { id: payload + '.' + await this.#signInSeal(payload), options };
  }

  async signIn(id: unknown, response: AuthenticationResponseJSON) {
    if (typeof id !== 'string' || !/^[0-9]{13}\.[A-Za-z0-9_-]{32,128}\.[a-f0-9]{64}$/u.test(id)) return null;
    const [deadline, challenge, seal] = id.split('.');
    const expires = Number(deadline);
    const origin = passkeyOrigin(this.env)!;
    const credential = await this.#credential();
    if (expires <= Date.now() || !credential || response?.id !== credential.id ||
        !timingSafeEqual(Buffer.from(seal), Buffer.from(await this.#signInSeal(deadline + '.' + challenge)))) return null;
    const verification = await verifyAuthenticationResponse({
      response, expectedChallenge: challenge, expectedOrigin: origin.origin,
      expectedRPID: origin.hostname, credential, requireUserVerification: true,
    }).catch(() => null);
    if (!verification?.verified) return null;
    const token = crypto.randomUUID() + crypto.randomUUID();
    const accepted = await this.ctx.storage.transaction(async tx => {
      const stored = await tx.get<WebAuthnCredential>('credential');
      const used = await tx.get<Record<string, number>>('used-owner-challenges') ?? {};
      const now = Date.now();
      if (expires <= now || used[challenge] > now ||
          stored?.id !== credential.id || stored.counter !== credential.counter) return false;
      const recent = Object.fromEntries(Object.entries(used).filter(([, deadline]) => deadline > now));
      await tx.put('credential', { ...credential, counter: verification.authenticationInfo.newCounter });
      await tx.put('used-owner-challenges', { ...recent, [challenge]: expires });
      await tx.put('owner-session', { hash: hashToken(token), expires: now + 30 * 60_000 });
      return true;
    });
    return accepted ? token : null;
  }

  async setupState(token: unknown) {
    if (!setupAuthorized(this.env, token)) return null;
    return { enrolled: Boolean(await this.#credential()) };
  }

  async enrollmentOptions(token: unknown) {
    if (!setupAuthorized(this.env, token)) return null;
    const origin = passkeyOrigin(this.env)!;
    const options = await generateRegistrationOptions({
      rpName: 'Maintenance approval', rpID: origin.hostname, userName: 'Owner',
      attestationType: 'none', supportedAlgorithmIDs: [-7],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    return this.ctx.storage.transaction(async tx => {
      if (await tx.get('credential')) return null;
      await tx.put<Enrollment>('enrollment', { challenge: options.challenge, expires: Date.now() + lifetime });
      return options;
    });
  }

  async enroll(token: unknown, response: RegistrationResponseJSON) {
    if (!setupAuthorized(this.env, token)) return false;
    const origin = passkeyOrigin(this.env)!;
    const enrollment = await this.ctx.storage.get<Enrollment>('enrollment');
    if (!enrollment || enrollment.expires <= Date.now() || await this.#credential()) return false;
    const verification = await verifyRegistrationResponse({
      response, expectedChallenge: enrollment.challenge, expectedOrigin: origin.origin,
      expectedRPID: origin.hostname, requireUserVerification: true,
    }).catch(() => null);
    if (!verification?.verified) return false;
    const credential = verification.registrationInfo.credential;
    const session = crypto.randomUUID() + crypto.randomUUID();
    return this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Enrollment>('enrollment');
      if (current?.challenge !== enrollment.challenge || current.expires <= Date.now() || await tx.get('credential')) return false;
      await tx.put('credential', credential);
      await tx.delete('enrollment');
      await tx.put('owner-session', { hash: hashToken(session), expires: Date.now() + 30 * 60_000 });
      return session;
    });
  }

  async prepareHost(token: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential()) return null;
    if (!this.env.HOST_PROBE) return { state: 'probe_unavailable' };
    const probe = await this.env.HOST_PROBE.prepareEnrollment().catch(() => ({ state: 'probe_unavailable' }));
    const inventory = await this.listHosts();
    const removals = await this.ctx.storage.list<Host>({ prefix: 'removing-host:' });
    const managedHosts = [
      ...inventory.hosts.map(({ address }) => ({ address, removalPending: false })),
      ...[...removals.values()].map(({ address }) => ({ address, removalPending: true })),
    ];
    return managedHosts.length ? { ...probe, managedHosts } : probe;
  }

  async startDeviceLogin(token: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential()) return false;
    return (await this.env.HOST_PROBE?.startDeviceLogin().catch(() => false)) ?? false;
  }

  async configureTailnet(token: unknown, clientId: unknown, clientSecret: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential() ||
        typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(clientId) ||
        typeof clientSecret !== 'string' || !/^[\x21-\x7e]{16,256}$/u.test(clientSecret)) return false;
    return (await this.env.HOST_PROBE?.configureTailnet(clientId, clientSecret).catch(() => false)) ?? false;
  }

  async removeHost(token: unknown, address: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential() ||
        typeof address !== 'string' || !validTailnetIpv4(address) || this.#changingHosts.has(address)) return null;
    this.#changingHosts.add(address);
    try {
      const slot = 'onboarding-host:' + address;
      const removal = 'removing-host:' + address;
      const host = await this.ctx.storage.transaction(async tx => {
        const previous = await tx.get<Host>(removal);
        if (previous) return previous;
        const legacy = await tx.get<Host>('onboarding-host');
        const current = await tx.get<Host>(slot) ?? (legacy?.address === address ? legacy : undefined);
        if (!current) return null;
        await tx.put(removal, current);
        if (current.signedApproval && current.enrollmentId) await tx.delete('host-approval-key:' + current.enrollmentId);
        await tx.delete(slot);
        if (legacy?.address === address) await tx.delete('onboarding-host');
        const pairId = await tx.get<string>('pairing-address:' + address);
        if (pairId) await tx.delete('pairing:' + pairId);
        await tx.delete('pairing-address:' + address);
        const legacyPair = await tx.get<Pairing>('pairing');
        if (legacyPair?.address === address) await tx.delete('pairing');
        await tx.delete('last-completed-host-check:' + address);
        return current;
      });
      if (!host) return { state: 'not_enrolled' };
      const removed = await this.env.HOST_PROBE?.removeEnrollmentHost(host).catch(() => false);
      if (!removed) return { state: 'removal_pending' };
      await this.ctx.storage.delete(removal);
      return { state: 'removed' };
    } finally {
      this.#changingHosts.delete(address);
    }
  }

  async beginAutomaticPairing(token: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential()) return null;
    if ((await this.prepareHost(token))?.state !== 'connected') return null;
    const pairingToken = randomPairingCode(pairingTokenLength);
    const id = await this.ctx.storage.transaction(async tx => {
      const id = await this.#unusedPairingId(tx);
      await tx.put<Pairing>('pairing:' + id, {
        id, address: '', automatic: true, commandExecution: true, signedApproval: true, account: maintenanceAccount,
        tokenHash: hashToken(pairingToken), expires: Date.now() + pairingLifetime,
      });
      return id;
    });
    return this.#pairingCommand(id, maintenanceAccount, pairingToken);
  }

  async #unusedPairingId(tx: DurableObjectTransaction) {
    let id = randomPairingCode(pairingIdLength);
    while (await tx.get<Pairing>('pairing:' + id)) id = randomPairingCode(pairingIdLength);
    return id;
  }

  #pairingCommand(id: string, account: HostAccount, pairingToken: string) {
    const url = new URL('/setup', passkeyOrigin(this.env));
    url.searchParams.set('pair', id);
    return {
      id, account, download: { url: url.href, token: pairingToken },
      installCommand: [
        'curl -fsS ' + shellQuote(url.href) + ' -H ' +
          shellQuote('Authorization: Bearer ' + pairingToken) + ' -o pasta-setup.sh &&',
        'sh pasta-setup.sh',
      ].join('\n'),
    };
  }

  async claimPairing(id: string | null, token: string, address: string | null) {
    if (!id || !validPairingId(id) || !validPairingToken(token) || !address || !validTailnetIpv4(address)) {
      return { error: 'This machine has no usable Tailscale IPv4 address.', status: 400 };
    }
    const slot = 'pairing:' + id;
    const pair = await this.ctx.storage.get<Pairing>(slot);
    const hash = hashToken(token);
    if (!pair?.automatic || pair.tokenHash !== hash || pair.expires <= Date.now()) {
      return { error: 'This command expired or was already used. Get a fresh one from the setup page.', status: 403 };
    }
    const probe = await this.env.HOST_PROBE?.prepareEnrollment().catch(() => undefined);
    if (probe?.state !== 'connected') return { error: 'PaSTA is not connected to Tailscale. Check the setup page.', status: 503 };
    const peer = probe.devices?.find(device => device.address === address);
    if (!peer) return { error: 'PaSTA cannot see this device. Check that both are on the same tailnet and that its policy allows access.', status: 403 };
    const claimed = await this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Pairing>(slot);
      if (!current || current.tokenHash !== hash || current.expires <= Date.now() ||
          (current.address && current.address !== address)) return false;
      const legacy = await tx.get<Host>('onboarding-host');
      if (legacy?.address === address || await tx.get('onboarding-host:' + address) ||
          await tx.get('removing-host:' + address)) return false;
      const addressSlot = 'pairing-address:' + address;
      const previousId = await tx.get<string>(addressSlot);
      if (previousId && previousId !== id) {
        const previous = await tx.get<Pairing>('pairing:' + previousId);
        if (previous?.fingerprint) return false;
        await tx.delete('pairing:' + previousId);
      }
      await tx.put(addressSlot, id);
      await tx.put(slot, { ...current, address, addressName: peer.name, probeAddress: probe.probeAddress });
      return true;
    });
    if (!claimed) return { error: 'This device is already paired or the command was claimed by another host.', status: 409 };
    const script = await this.pairingScript(id, token, true);
    return script ? { script, status: 200 } : { error: 'PaSTA could not prepare the SSH key. Run the command again.', status: 503 };
  }

  async beginPairing(token: unknown, address: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential() ||
        typeof address !== 'string' || !validTailnetIpv4(address)) return null;
    if (this.#changingHosts.has(address)) return null;
    this.#changingHosts.add(address);
    try {
      if (await this.ctx.storage.get('removing-host:' + address)) return null;
      return await this.#beginPairing(token, address);
    } finally {
      this.#changingHosts.delete(address);
    }
  }

  async #beginPairing(token: unknown, address: string) {
    const probe = await this.prepareHost(token);
    if (probe?.state !== 'connected') return null;
    const callbackToken = randomPairingCode(pairingTokenLength);
    const pairing = await this.ctx.storage.transaction(async tx => {
      const slot = 'pairing-address:' + address;
      const previousId = await tx.get<string>(slot);
      const previous = previousId ? await tx.get<Pairing>('pairing:' + previousId) : undefined;
      if (previous?.fingerprint) return previous;
      const id = await this.#unusedPairingId(tx);
      if (previousId) await tx.delete('pairing:' + previousId);
      const next = { id, address, probeAddress: probe.probeAddress, commandExecution: true, signedApproval: true, account: maintenanceAccount, tokenHash: hashToken(callbackToken), expires: Date.now() + pairingLifetime };
      await tx.put('pairing:' + id, next);
      await tx.put(slot, id);
      return next;
    });
    if (!pairing) return null;
    if (pairing.fingerprint) return { id: pairing.id };
    return this.#pairingCommand(pairing.id, pairing.account ?? legacyAccount, callbackToken);
  }

  async #pairingApprovalKey(id: string) {
    const key = 'host-approval-key:' + id;
    return this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<ReturnType<typeof createHostApprovalKey>>(key);
      if (existing) return existing;
      const created = createHostApprovalKey();
      await tx.put(key, created);
      return created;
    });
  }

  async pairingScript(id: string | null, token: string, claimed = false) {
    if (!id || !validPairingId(id) || !validPairingToken(token)) return null;
    const pair = await this.ctx.storage.get<Pairing>('pairing:' + id);
    if (!pair || !pair.tokenHash || pair.fingerprint || pair.expires <= Date.now() ||
        !timingSafeEqual(Buffer.from(pair.tokenHash), Buffer.from(hashToken(token)))) return null;
    if (pair.automatic && !claimed) {
      const claimUrl = new URL(prefix + '/claim-host', passkeyOrigin(this.env));
      claimUrl.searchParams.set('pair', id);
      return [
        '#!/bin/sh', 'pairing_token=' + shellQuote(token),
        'claim_url=' + shellQuote(claimUrl.href), pairingDetector,
      ].join('\n');
    }
    const account = pair.account ?? legacyAccount;
    const install = await this.env.HOST_PROBE?.prepareHostKey(pair.address, account, pair.commandExecution).catch(() => null);
    if (!install) return null;
    const approvalKey = pair.signedApproval ? await this.#pairingApprovalKey(id) : undefined;
    const url = new URL(prefix + '/host-pairing', passkeyOrigin(this.env));
    url.searchParams.set('pair', id);
    return [
      '#!/bin/sh',
      'target_address=' + shellQuote(pair.address),
      'probe_address=' + shellQuote(validTailnetIpv4(pair.probeAddress) ? pair.probeAddress! : ''),
      'target_name=' + shellQuote((pair.addressName ?? pair.address).replace(/[\x00-\x1f\x7f]/gu, '').slice(0, 160)),
      'account=' + shellQuote(account),
      'command_execution=' + (pair.commandExecution ? 'yes' : 'no'),
      'pairing_token=' + shellQuote(token),
      'callback_url=' + shellQuote(url.href),
      'result_url=' + shellQuote(pair.automatic ? new URL(prefix + '/pair-result?pair=' + id, passkeyOrigin(this.env)).href : ''),
      'install_command=' + shellQuote(install),
      'approval_gate=' + shellQuote(approvalKey ? hostApprovalGate : ''),
      'approval_public_key=' + shellQuote(approvalKey?.publicKey ?? ''),
      'approval_target=' + shellQuote(JSON.stringify({ host: pair.address, enrollment: id })),
      pairingInstaller,
    ].join('\n');
  }

  async cancelPairing(token: unknown, id: unknown) {
    if (!await this.#ownerAuthorized(token) || !await this.#credential() ||
        typeof id !== 'string' || !validPairingId(id)) return null;
    const slot = 'pairing:' + id;
    const pending = await this.ctx.storage.transaction(async tx => {
      const pair = await tx.get<Pairing>(slot);
      if (!pair || pair.fingerprint) return pair;
      const addressSlot = 'pairing-address:' + pair.address;
      if (await tx.get<string>(addressSlot) === id) await tx.delete(addressSlot);
      await tx.delete('host-approval-key:' + id);
      await tx.delete(slot);
      return undefined;
    });
    if (!pending?.fingerprint) return { state: 'invalidated' };
    if (!pending.automatic || pending.check?.state === 'verified') return { state: 'already_paired' };
    const address = pending.address;
    if (!pending.check || this.#changingHosts.has(address)) return { state: 'verification_pending' };
    this.#changingHosts.add(address);
    try {
      const host: Host = { address, fingerprint: pending.fingerprint, account: pending.account, enrollmentId: id,
        commandExecution: pending.commandExecution, signedApproval: pending.signedApproval };
      if (await this.ctx.storage.get('onboarding-host:' + address)) return { state: 'already_paired' };
      const removed = await this.env.HOST_PROBE?.removeEnrollmentHost(host).catch(() => false);
      if (!removed) return { state: 'removal_pending' };
      await this.ctx.storage.transaction(async tx => {
        const addressSlot = 'pairing-address:' + address;
        if (await tx.get<string>(addressSlot) === id) await tx.delete(addressSlot);
        await tx.delete('host-approval-key:' + id);
        await tx.delete(slot);
      });
      return { state: 'invalidated' };
    } finally {
      this.#changingHosts.delete(address);
    }
  }

  async receiveFingerprint(id: string | null, callbackToken: string, fingerprint: unknown, accountAction: unknown, selectedAccount: unknown) {
    if ((id !== null && !validPairingId(id)) || !validPairingToken(callbackToken)) return false;
    const canceled = accountAction === 'canceled';
    const candidateFingerprint = typeof fingerprint === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/u.test(fingerprint)
      ? fingerprint : undefined;
    if (canceled ? fingerprint !== null : !candidateFingerprint) return false;
    const accepted = await this.ctx.storage.transaction(async tx => {
      const slot = id === null ? 'pairing' : 'pairing:' + id;
      const pair = await tx.get<Pairing>(slot);
      if (!pair || !pair.address || pair.fingerprint || pair.expires <= Date.now() || pair.tokenHash !== hashToken(callbackToken)) return false;
      if (canceled) {
        await tx.put<Pairing>(slot, { ...pair, accountAction: 'canceled', tokenHash: '' });
        return true;
      }
      const dedicated = accountAction === 'created' || accountAction === 'reused';
      const existing = accountAction === 'existing' && isHostAccount(selectedAccount);
      if (accountAction === 'existing' && !existing) return false;
      if (!existing && selectedAccount !== null && selectedAccount !== pair.account) return false;
      if (pair.account && !dedicated && !existing) return false;
      await tx.put<Pairing>(slot, {
        ...pair, fingerprint: candidateFingerprint, tokenHash: '', receiptHash: pair.automatic ? pair.tokenHash : undefined,
        account: existing ? selectedAccount : pair.account,
        accountAction: dedicated || existing ? accountAction : undefined,
      });
      return true;
    });
    if (accepted && !canceled && id) {
      const slot = 'pairing:' + id;
      const pair = await this.ctx.storage.get<Pairing>(slot);
      if (pair?.automatic) this.#startPairingCheck(pair, slot);
    }
    return accepted;
  }

  async pairingReceipt(id: string | null, token: string) {
    if (!id || !validPairingId(id) || !validPairingToken(token)) return null;
    const pair = await this.ctx.storage.get<Pairing>('pairing:' + id);
    if (!pair?.receiptHash || pair.expires <= Date.now() || pair.receiptHash !== hashToken(token)) return null;
    if (!pair.check || this.#finishingPairings.has(id)) return 'verifying';
    return pair.check.state === 'verified' ? 'verified' : 'verification_failed';
  }

  async finishPairing(token: unknown, id: unknown, retry = false) {
    if (!await this.#ownerAuthorized(token) || typeof id !== 'string') return null;
    const next = 'pairing:' + id;
    const slot = await this.ctx.storage.get<Pairing>(next) ? next : 'pairing';
    const pair = await this.ctx.storage.get<Pairing>(slot);
    if (pair?.id === id && pair.accountAction === 'canceled') return { state: 'pairing_canceled' };
    if (pair?.id !== id || (!pair.fingerprint && pair.expires <= Date.now())) return { state: 'pairing_expired' };
    if (!pair.fingerprint) return { state: pair.address && pair.automatic ? 'waiting_for_confirmation' : 'waiting_for_host', host: pair.automatic ? pair.addressName : undefined };
    const finishing = this.#finishingPairings.get(id);
    if (finishing) return pair.automatic ? { state: 'verifying', host: pair.addressName } : finishing;
    if (pair.automatic && pair.check?.state === 'verified') return { state: 'verified', host: pair.addressName ?? pair.address };
    if (pair.automatic && pair.check && !retry) return { state: 'verification_failed', failure: pair.check.state };
    const tracked = this.#startPairingCheck(pair, slot);
    if (!tracked) return { state: 'verifying', host: pair.addressName };
    return pair.automatic ? { state: 'verifying', host: pair.addressName } : tracked;
  }

  #startPairingCheck(pair: Pairing, slot: string) {
    if (this.#changingHosts.has(pair.address)) return null;
    const id = pair.id;
    this.#changingHosts.add(pair.address);
    const operation = pair.automatic ? this.#verifyAutomaticPairing(pair, slot) : this.#finishPairing(pair, slot, id);
    const tracked = operation.finally(() => {
      this.#finishingPairings.delete(id);
      this.#changingHosts.delete(pair.address);
    });
    this.#finishingPairings.set(id, tracked);
    if (pair.automatic) this.ctx.waitUntil(tracked);
    return tracked;
  }

  async #verifyAutomaticPairing(pair: Pairing, slot: string) {
    if (!pair.fingerprint || !this.env.HOST_PROBE) return { state: 'verification_failed', failure: 'unconfigured' };
    if (!await this.ctx.storage.get(slot)) return { state: 'pairing_canceled' };
    const host: Host = { address: pair.address, fingerprint: pair.fingerprint, account: pair.account, enrollmentId: pair.id, commandExecution: pair.commandExecution, signedApproval: pair.signedApproval };
    let check: HostResult = { state: 'check_outcome_unknown', executed: null };
    try {
      if (await this.env.HOST_PROBE.saveEnrollmentHost(host)) {
        check = await this.env.HOST_PROBE.runHostEnrollmentCheck(host);
      } else {
        check = { state: 'target_changed', executed: false };
      }
    } catch { /* The owner can retry this fixed read-only check. */ }
    await this.ctx.storage.transaction(async tx => {
      if (check.state === 'verified') await tx.put('onboarding-host:' + pair.address, host);
      await tx.put(slot, { ...pair, check });
    });
    return check.state === 'verified' ? { state: 'verified', host: pair.addressName ?? pair.address }
      : { state: 'verification_failed', failure: check.state };
  }

  async #finishPairing(pair: Pairing, slot: string, id: string) {
    const current = await this.ctx.storage.get<Pairing>(slot);
    if (current?.id !== id || !pair.fingerprint ||
        await this.ctx.storage.get('removing-host:' + pair.address)) return null;
    const legacy = await this.ctx.storage.get<Host>('onboarding-host');
    const host = {
      address: pair.address, fingerprint: pair.fingerprint, account: pair.account, commandExecution: pair.commandExecution, signedApproval: pair.signedApproval,
      enrollmentId: slot === 'pairing' || (legacy?.address === pair.address && legacy.fingerprint === pair.fingerprint)
        ? undefined : pair.id,
    };
    const existing = await this.ctx.storage.get<Host>('onboarding-host:' + pair.address);
    if (existing?.fingerprint === pair.fingerprint && !existing.enrollmentId) host.enrollmentId = undefined;
    const saved = await this.env.HOST_PROBE?.saveEnrollmentHost(host).catch(() => false);
    if (!saved) return null;
    const reviewJobId = await this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Pairing>(slot);
      if (current?.id !== id || current.fingerprint !== pair.fingerprint) return null;
      await tx.put<Host>('onboarding-host:' + host.address, host);
      const jobId = current.reviewJobId ?? id;
      const job = await tx.get<Job>('job:' + jobId);
      if (!job || job.approved_at || job.expires_at > Date.now()) return jobId;
      const replacement = crypto.randomUUID();
      await tx.put<Pairing>(slot, { ...current, reviewJobId: replacement });
      return replacement;
    });
    if (!reviewJobId) return null;
    return { ...await this.start(reviewJobId, true, host.address), account_action: pair.accountAction };
  }

  async #pairedHostName(address: string, fingerprint: string, enrollmentId?: string) {
    if (!enrollmentId) return undefined;
    const pair = await this.ctx.storage.get<Pairing>('pairing:' + enrollmentId);
    if (pair?.address !== address || pair.fingerprint !== fingerprint) return undefined;
    return pair.addressName?.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '').trim().slice(0, 160) || undefined;
  }

  async requestCommand(jobId: string, address: string, command: string, statement: string) {
    const parser = await classify(command).catch(() => undefined);
    if (!parser) return { state: 'command_validation_unavailable', ...empty };
    if (parser.decision === 'invalid') return { state: 'invalid_command', reason: parser.reason, ...empty };
    return this.start(jobId, true, address, command === commandRestart, command, statement, parser);
  }

  async start(jobId: string, enrollment = false, address?: string, restart = false, command?: string, statement?: string, parser?: Awaited<ReturnType<typeof classify>>) {
    const origin = passkeyOrigin(this.env)!;
    const credential = await this.#credential();
    if (!credential) return { state: 'enrollment_required', ...empty };
    const key = 'job:' + jobId;
    if (address && !validTailnetIpv4(address)) return { state: 'host_setup_required', ...empty };
    let host: Host | undefined;
    if (enrollment) {
      const legacy = await this.ctx.storage.get<Host>('onboarding-host');
      const hosts = address ? undefined : await this.ctx.storage.list<Host>({ prefix: 'onboarding-host:', limit: 2 });
      if (hosts?.size === 2 || (hosts?.size === 1 && legacy && !hosts.has('onboarding-host:' + legacy.address))) {
        return { state: 'host_selection_required', ...empty };
      }
      host = address ? await this.ctx.storage.get<Host>('onboarding-host:' + address) ??
        (legacy?.address === address ? legacy : undefined) : hosts?.values().next().value ?? legacy;
    }
    if (enrollment && !host) return { state: 'host_setup_required', ...empty };
    const dynamic = Boolean(command && host?.signedApproval);
    if (command && host?.commandExecution && !host.signedApproval) {
      return { state: 'host_command_setup_required', ...empty };
    }
    if (command && !dynamic && command !== commandCheck && command !== commandRestart) {
      return { state: 'host_command_setup_required', ...empty };
    }
    const target = host ? {
      ...hostCheck, host: host.address, fingerprint: host.fingerprint,
      execution_identity: host.account ?? legacyAccount, enrollmentId: host.enrollmentId,
      commandExecution: host.commandExecution, signedApproval: host.signedApproval,
      operation: dynamic ? commandOperation : restart ? restartOperation : hostCheck.operation,
    } : diagnostic;
    const options = await generateAuthenticationOptions({
      rpID: origin.hostname, userVerification: 'required',
      allowCredentials: [{ id: credential.id, transports: credential.transports }],
    });
    const hostName = command && host ? await this.#pairedHostName(host.address, host.fingerprint, host.enrollmentId) : undefined;
    let scope: string | undefined;
    if (command && !await this.ctx.storage.get<Job>(key)) {
      scope = parser
        ? await assessScope(this.env.AI, command, { screening_reason: parser.reason, syntax_facts: parser.syntax_facts })
        : scopeUnavailable;
    }
    const matches = await this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<Job>(key);
      if (existing) return existing.command === command && existing.statement === statement && existing.target.operation === target.operation &&
        existing.target.host === target.host && (target.dry_run || (!existing.target.dry_run &&
          existing.target.fingerprint === target.fingerprint && existing.target.execution_identity === target.execution_identity && existing.target.enrollmentId === target.enrollmentId &&
          Boolean(existing.target.commandExecution) === Boolean(target.commandExecution) &&
          Boolean(existing.target.signedApproval) === Boolean(target.signedApproval)));
      await tx.put<Job>(key, { target, options, ...(command ? { command, statement, hostName, scope } : {}), expires_at: Date.now() + this.#jobLifetime() });
      return true;
    });
    if (!matches) return { state: 'job_id_in_use', ...empty };
    const status = await this.status(jobId);
    return status.state === 'pending'
      ? { ...status, review_url: new URL(prefix + '/review?job=' + jobId, origin).href }
      : status;
  }

  async #scheduleRetention() {
    if (await this.ctx.storage.getAlarm() === null) {
      await this.ctx.storage.setAlarm(Date.now() + retentionScanInterval);
    }
  }

  async alarm() {
    const cursor = await this.ctx.storage.get<string>('job-retention-cursor');
    const batch = await this.ctx.storage.list<Job>({
      prefix: 'job:', limit: 100, ...(cursor ? { startAfter: cursor } : {}),
    });
    for (const [key, job] of batch) {
      if (job.expires_at + reviewRetention > Date.now()) continue;
      await this.ctx.storage.transaction(async tx => {
        const current = await tx.get<Job>(key);
        if (!current || current.expires_at + reviewRetention > Date.now()) return;
        const { command, statement, scope, host_result, ...summary } = current;
        if (command === undefined && statement === undefined && scope === undefined &&
            (!host_result || !('stdout' in host_result || 'stderr' in host_result))) return;
        if (host_result) {
          const { stdout, stderr, ...result } = host_result as typeof host_result & { stdout?: string; stderr?: string };
          summary.host_result = result as HostResult;
        }
        await tx.put<Job>(key, summary);
      });
    }
    if (batch.size === 100) {
      await this.ctx.storage.put('job-retention-cursor', [...batch.keys()].at(-1)!);
      await this.ctx.storage.setAlarm(Date.now() + 1000);
    } else {
      await this.ctx.storage.delete('job-retention-cursor');
      await this.ctx.storage.setAlarm(Date.now() + retentionScanInterval);
    }
  }

  async status(jobId: string, includeOutput = true) {
    await this.#scheduleRetention();
    const job = await this.ctx.storage.get<Job>('job:' + jobId);
    if (!job) return { state: 'unknown', ...empty };
    const checkingState = job.approved_at &&
      (job.execution_owner !== this.#executionOwner || Date.now() >= job.approved_at + lifetime)
      ? 'check_outcome_unknown' : 'checking_host';
    const approvedState = job.target.dry_run ? 'verified_dry_run' : job.host_result?.state ?? job.host_verification ?? checkingState;
    const { host, operation, execution_identity, dry_run } = job.target;
    const hostResult = job.host_result;
    const retained = job.expires_at + reviewRetention > Date.now();
    const hiddenOutput = (!includeOutput || !retained) && hostResult
      ? { stdout: undefined, stderr: undefined } : {};
    return {
      job_id: jobId, host, operation, execution_identity, dry_run,
      ...(retained && job.command ? {
        command: job.command,
        statement: job.statement,
        host_name: job.hostName ?? (job.target.dry_run ? undefined :
          await this.#pairedHostName(host, job.target.fingerprint, job.target.enrollmentId)),
        explanation: job.scope ?? scopeUnavailable,
      } : {}),
      ...(!job.target.dry_run ? { fingerprint: job.target.fingerprint } : {}),
      ...(operation === restartOperation ? { service: restartUnit, run_as: 'root via sudo' } : {}), expires_at: job.expires_at,
      ...hostResult,
      ...hiddenOutput,
      executed: job.host_result ? job.host_result.executed : (
        job.approved_at && !job.target.dry_run ? null : false
      ),
      state: job.approved_at ? approvedState : job.expires_at <= Date.now() ? 'expired' : 'pending',
      approved_at: job.approved_at ?? null,
      can_reconcile: Boolean(job.retry_lock && !job.reconciled_at && (hostResult ?
        hostResult.executed === null : job.approved_at && Date.now() >= job.approved_at + lifetime)),
    };
  }

  async listHosts() {
    const hosts = await this.ctx.storage.list<Host>({ prefix: 'onboarding-host:' });
    const legacy = await this.ctx.storage.get<Host>('onboarding-host');
    if (legacy && !hosts.has('onboarding-host:' + legacy.address)) {
      hosts.set('onboarding-host:' + legacy.address, legacy);
    }
    return { hosts: [...hosts.values()].map(({ address }) => ({ address })), ...empty };
  }

  async hostStatus(address?: string) {
    if (address && !validTailnetIpv4(address)) return { state: 'host_setup_required', ...empty };
    const latest = await this.ctx.storage.get<string>(address ? 'last-completed-host-check:' + address : 'last-completed-host-check');
    if (latest) return this.status(latest);
    if (address) {
      const host = await this.ctx.storage.get<Host>('onboarding-host:' + address);
      const legacy = await this.ctx.storage.get<Host>('onboarding-host');
      if (!host && legacy?.address !== address) return { state: 'host_setup_required', ...empty };
      const previous = await this.ctx.storage.get<string>('last-completed-host-check');
      const result = previous ? await this.status(previous) : undefined;
      if (result && 'host' in result && result.host === address) return result;
    }
    return { host: address ?? hostCheck.host, state: this.env.HOST_PROBE ? 'awaiting_check' : 'unconfigured', ...empty };
  }

  async reviewOptions(jobId: string) {
    const job = await this.ctx.storage.get<Job>('job:' + jobId);
    if (!job || job.approved_at || job.expires_at <= Date.now() ||
        (!job.target.dry_run && !isHostOperation(job.target.operation))) return null;
    return job.options;
  }

  async reconcile(jobId: string) {
    const key = 'job:' + jobId;
    return this.ctx.storage.transaction(async tx => {
      const job = await tx.get<Job>(key);
      if (!job?.approved_at || !job.retry_lock || await tx.get(job.retry_lock) !== key) return false;
      const ambiguous = job.host_result ? job.host_result.executed === null :
        Date.now() >= job.approved_at + lifetime;
      if (!ambiguous) return false;
      await tx.delete(job.retry_lock);
      await tx.put<Job>(key, { ...job, reconciled_at: Date.now() });
      return true;
    });
  }

  async approve(jobId: string, response: AuthenticationResponseJSON) {
    const origin = passkeyOrigin(this.env)!;
    const key = 'job:' + jobId;
    const job = await this.ctx.storage.get<Job>(key);
    const credential = await this.#credential();
    if (!credential || !job || job.approved_at || job.expires_at <= Date.now() ||
        (!job.target.dry_run && !isHostOperation(job.target.operation))) return false;
    const verification = await verifyAuthenticationResponse({
      response, expectedChallenge: job.options.challenge, expectedOrigin: origin.origin,
      expectedRPID: origin.hostname, credential, requireUserVerification: true,
    }).catch(() => null);
    if (!verification?.verified) return false;
    const retryLock = !job.target.dry_run &&
      (job.target.operation === commandOperation || job.target.operation === restartOperation)
      ? 'retry-lock:' + hashToken(JSON.stringify([
        job.target.host, job.target.execution_identity, job.command ?? commandRestart,
      ]))
      : undefined;
    const accepted = await this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Job>(key);
      const stored = await tx.get<WebAuthnCredential>('credential');
      if (!current || current.approved_at || current.expires_at <= Date.now() ||
          stored?.id !== credential.id || stored.counter !== credential.counter) return false;
      if (retryLock) {
        if (await tx.get(retryLock)) return false;
        await tx.put(retryLock, key);
      }
      await tx.put('credential', { ...credential, counter: verification.authenticationInfo.newCounter });
      await tx.put<Job>(key, { ...current, approved_at: Date.now(), execution_owner: this.#executionOwner,
        ...(retryLock ? { retry_lock: retryLock } : {}),
      });
      return true;
    });
    if (accepted && !job.target.dry_run) {
      const expected = {
        address: job.target.host, fingerprint: job.target.fingerprint, enrollmentId: job.target.enrollmentId, account: job.target.execution_identity,
        commandExecution: job.target.commandExecution, signedApproval: job.target.signedApproval,
      };
      this.ctx.waitUntil(this.#verifyHost(key, expected, job.target.operation, job.command));
    }
    return accepted;
  }

  async #verifyHost(key: string, expected: Host, operation: string, command?: string) {
    let result: HostResult = { state: 'unconfigured', executed: false };
    const enrolled = await this.ctx.storage.get<Host>('onboarding-host:' + expected.address);
    const legacy = await this.ctx.storage.get<Host>('onboarding-host');
    const removing = await this.ctx.storage.get('removing-host:' + expected.address);
    if (removing || !sameEnrollmentHost(enrolled ?? legacy, expected)) {
      result = { state: 'target_changed', executed: false };
    } else if (this.env.HOST_PROBE && validEnrollmentHost(expected)) {
      const signingKey = operation === commandOperation && expected.signedApproval && expected.enrollmentId
        ? await this.ctx.storage.get<ReturnType<typeof createHostApprovalKey>>('host-approval-key:' + expected.enrollmentId)
        : undefined;
      const authorization = command && signingKey && expected.enrollmentId && expected.account
        ? signHostApproval(signingKey.privateKey, {
          job: key.slice('job:'.length), enrollment: expected.enrollmentId,
          host: expected.address, account: expected.account, command,
        }) : undefined;
      const action = operation === commandOperation
        ? authorization ? this.env.HOST_PROBE.runApprovedCommand(expected, authorization)
          : Promise.resolve({ state: 'unconfigured' as const, executed: false as const })
        : operation === restartOperation ? this.env.HOST_PROBE.restartDemoService(expected)
        : this.env.HOST_PROBE.runHostEnrollmentCheck(expected);
      result = await action.catch(() => ({ state: 'check_outcome_unknown', executed: null }));
    }
    await this.ctx.storage.transaction(async tx => {
      const job = await tx.get<Job>(key);
      if (!job?.approved_at) return;
      await tx.put<Job>(key, { ...job, host_result: result });
      if (result.executed !== null && job.retry_lock && await tx.get(job.retry_lock) === key) {
        await tx.delete(job.retry_lock);
      }
      const current = await tx.get<Host>('onboarding-host:' + expected.address);
      const legacyHost = await tx.get<Host>('onboarding-host');
      if (operation !== hostCheck.operation || !sameEnrollmentHost(current ?? legacyHost, expected)) return;
      for (const slot of ['last-completed-host-check', 'last-completed-host-check:' + expected.address]) {
        const previous = await tx.get<string>(slot);
        const previousJob = previous ? await tx.get<Job>('job:' + previous) : undefined;
        if (!previousJob?.approved_at || previousJob.approved_at <= job.approved_at) {
          await tx.put(slot, key.slice('job:'.length));
        }
      }
    });
  }
}

export const approvalStore = (env: PasskeyEnv) => env.PASSKEYS.getByName('owner-v1');

const headers = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
};

export async function passkeyRoute(request: Request, env: PasskeyEnv) {
  const url = new URL(request.url);
  const origin = passkeyOrigin(env);
  const reject = (status: number) => new Response(null, { status, headers });
  if (url.origin !== origin?.origin) return reject(404);
  const store = approvalStore(env);
  const path = url.pathname.slice(prefix.length);
  if (request.method === 'GET') {
    if (url.pathname === '/setup') {
      const auth = request.headers.get('Authorization') ?? '';
      if (!auth.startsWith('Bearer ')) return reject(403);
      const script = await store.pairingScript(url.searchParams.get('pair'), auth.slice(7));
      return script ? new Response(script, { headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' } }) : reject(403);
    }
    if (path === '/pair-result') {
      const authorization = request.headers.get('Authorization') ?? '';
      if (!authorization.startsWith('Bearer ')) return reject(403);
      const state = await store.pairingReceipt(url.searchParams.get('pair'), authorization.slice(7));
      return state ? new Response(state + '\n', { headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' } }) : reject(403);
    }
    if (path === '/setup-preview') {
      return new Response('#!/bin/sh\n' + pairingDetector, {
        headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }
    if (path === '/style.css') {
      return new Response(approvalStyles, { headers: { ...headers, 'Content-Type': 'text/css; charset=utf-8' } });
    }
    if (path === '/onboard' || path === '/review') {
      return new Response(approvalPage, { headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (path === '/browser.js') {
      return new Response(browserBundle, { headers: { ...headers, 'Content-Type': 'text/javascript; charset=utf-8' } });
    }
    return reject(404);
  }
  if (request.method !== 'POST') return reject(405);
  const length = request.headers.get('Content-Length');
  if (!length || !/^\d{1,6}$/.test(length) || Number(length) > 32768) return reject(413);
  if (path === '/claim-host') {
    const auth = request.headers.get('Authorization') ?? '';
    if (!auth.startsWith('Bearer ') || Number(length) > 128 ||
        request.headers.get('Content-Type')?.split(';', 1)[0].trim() !== 'application/x-www-form-urlencoded') return reject(403);
    const form = new URLSearchParams(await request.text());
    const claimed = await store.claimPairing(url.searchParams.get('pair'), auth.slice(7), form.get('address'));
    return new Response(claimed.script ?? claimed.error + '\n', {
      status: claimed.status, headers: { ...headers, 'Content-Type': 'text/plain; charset=utf-8' },
    });
  }
  if (path === '/host-pairing') {
    const auth = request.headers.get('Authorization') ?? '';
    const mediaType = request.headers.get('Content-Type')?.split(';', 1)[0].trim();
    if (!auth.startsWith('Bearer ') || Number(length) > 1024 ||
        mediaType !== 'application/x-www-form-urlencoded') return reject(403);
    const form = new URLSearchParams(await request.text());
    return await store.receiveFingerprint(url.searchParams.get('pair'), auth.slice(7), form.get('fingerprint'), form.get('account_action'), form.get('account'))
      ? new Response(form.get('account_action') === 'canceled' ? 'Pairing canceled.\n' : 'Host fingerprint received.\n', { headers })
      : reject(403);
  }
  if (request.headers.get('Origin') !== origin.origin) return reject(403);
  if (request.headers.get('Content-Type') !== 'application/json') return reject(415);
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return reject(400);
  const reply = (data: unknown) => Response.json(data, { headers });
  if (path === '/owner-state') return reply(await store.ownerState());
  if (path === '/sign-in-options') {
    const options = await store.signInOptions();
    return options ? reply(options) : reject(403);
  }
  if (path === '/sign-in') {
    const token = await store.signIn(body.id, body.response as AuthenticationResponseJSON);
    return token ? reply({ token }) : reject(403);
  }
  if (path === '/setup-state') {
    const setup = await store.setupState(body.token);
    return setup ? reply(setup) : reject(403);
  }
  if (path === '/enrollment-options') {
    const options = await store.enrollmentOptions(body.token);
    return options ? reply(options) : reject(403);
  }
  if (path === '/enroll') {
    const token = await store.enroll(body.token, body.response as RegistrationResponseJSON);
    return token ? reply({ enrolled: true, token }) : reject(403);
  }
  if (path === '/prepare-host') {
    const setup = await store.prepareHost(body.token);
    return setup ? reply(setup) : reject(403);
  }
  if (path === '/start-device-login') {
    return await store.startDeviceLogin(body.token) ? reply({ started: true }) : reject(403);
  }
  if (path === '/configure-tailnet') {
    const connected = await store.configureTailnet(body.token, body.clientId, body.clientSecret);
    return connected ? reply({ configured: true }) : reject(403);
  }
  if (path === '/remove-host') {
    const removed = await store.removeHost(body.token, body.address);
    return removed ? reply(removed) : reject(403);
  }
  if (path === '/begin-host-pairing') {
    const pair = body.address === undefined ? await store.beginAutomaticPairing(body.token) : await store.beginPairing(body.token, body.address);
    return pair ? reply(pair) : reject(403);
  }
  if (path === '/cancel-pairing') {
    const result = await store.cancelPairing(body.token, body.id);
    return result ? reply(result) : reject(403);
  }
  if (path === '/finish-host-pairing') {
    const result = await store.finishPairing(body.token, body.id, body.retry === true);
    return result ? reply(result) : reject(403);
  }
  if (typeof body.job !== 'string' || !uuid.test(body.job)) return reject(400);
  if (['/review-options', '/approve', '/job-status', '/reconcile'].includes(path) &&
      !await store.authorizeReview(body.token)) return reject(403);
  if (path === '/review-options') {
    const options = await store.reviewOptions(body.job);
    return options ? reply({ options, job: await store.status(body.job, false) }) : reject(409);
  }
  if (path === '/approve') {
    return await store.approve(body.job, body.response as AuthenticationResponseJSON)
      ? reply(await store.status(body.job, false)) : reject(409);
  }
  if (path === '/reconcile') return await store.reconcile(body.job) ? reply({ reconciled: true }) : reject(409);
  if (path === '/job-status') return reply(await store.status(body.job, false));
  return reject(404);
}
