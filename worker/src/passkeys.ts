import { DurableObject } from 'cloudflare:workers';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  generateAuthenticationOptions, generateRegistrationOptions,
  verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type RegistrationResponseJSON, type WebAuthnCredential,
} from '@simplewebauthn/server';
import browserBundle from './passkey-browser.txt';
import approvalPage from './passkey-page.html';
import approvalStyles from './passkey-page.css';
import { sameEnrollmentHost, restartUnit, validEnrollmentHost, validTailnetIpv4, legacyAccount, maintenanceAccount, type HostAccount, type Host, type TailnetDevice } from '../../experiments/tailnet/credentials';

const lifetime = 5 * 60_000;
const prefix = '/passkeys';
const empty = { executed: false };
const diagnostic = { host: 'ams', operation: 'openbot-enrollment-check-v1', execution_identity: maintenanceAccount, dry_run: true } as const;
const hostCheck = { ...diagnostic, operation: 'run openbot-enrollment-check-v1 to verify SSH enrollment', dry_run: false } as const;
const restartOperation = 'restart ' + restartUnit;
const isHostOperation = (operation: string) => operation === hostCheck.operation || operation === restartOperation;
type HostVerification = 'unconfigured' | 'target_changed' | 'host_key_unverified' | 'ssh_authentication_failed' | 'verified' | 'connection_failed';
type HostResult =
  | { state: 'verified' | 'service_restarted'; executed: true; stdout: string; exit_status: 0 }
  | { state: 'unconfigured' | 'target_changed' | 'host_key_unverified' | 'ssh_authentication_failed'; executed: false }
  | { state: 'diagnostic_failed' | 'restart_failed' | 'check_outcome_unknown'; executed: null; exit_status?: number | null };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
type Job = {
  target: typeof diagnostic | (Omit<typeof hostCheck, 'host' | 'operation' | 'execution_identity'> & { host: string; fingerprint: string; enrollmentId?: string; operation: string; execution_identity: HostAccount });
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  expires_at: number;
  approved_at?: number;
  execution_owner?: string;
  host_verification?: HostVerification;
  host_result?: HostResult;
};
type Enrollment = { challenge: string; expires: number };
type Pairing = { id: string; address: string; tokenHash: string; expires: number; fingerprint?: string; reviewJobId?: string; account?: HostAccount; accountAction?: 'created' | 'reused' | 'canceled' };
const pairingLifetime = 15 * 60_000;
const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
const shellQuote = (value: string) => "'" + value.replaceAll("'", "'\"'\"'") + "'";
export type PasskeyEnv = {
  PASSKEYS: DurableObjectNamespace<PasskeyApproval>;
  PASSKEY_ORIGIN?: string;
  PASSKEY_SETUP_TOKEN?: string;
  PASSKEY_LOCAL_TEST_JOB_TTL_MS?: string;
  HOST_PROBE?: {
    runHostEnrollmentCheck(expected: Host): Promise<HostResult>;
    restartDemoService(expected: Host): Promise<HostResult>;
    prepareEnrollment(): Promise<{ state: string; installCommand?: string; deviceTag?: string; devices?: TailnetDevice[]; loginUrl?: string; needsDeviceApproval?: boolean }>;
    startDeviceLogin(): Promise<boolean>;
    removeEnrollmentHost(expected: Host): Promise<boolean>;
    prepareHostKey(address: string, account: HostAccount): Promise<string | null>;
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
  #finishingPairings = new Map<string, Promise<Awaited<ReturnType<PasskeyApproval['start']>> | null>>();

  #credential() { return this.ctx.storage.get<WebAuthnCredential>('credential'); }

  #jobLifetime() {
    const testLifetime = Number(this.env.PASSKEY_LOCAL_TEST_JOB_TTL_MS);
    return passkeyOrigin(this.env)?.protocol === 'http:' &&
      Number.isSafeInteger(testLifetime) && testLifetime > 0 && testLifetime < lifetime ? testLifetime : lifetime;
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
    return this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Enrollment>('enrollment');
      if (current?.challenge !== enrollment.challenge || current.expires <= Date.now() || await tx.get('credential')) return false;
      await tx.put('credential', credential);
      await tx.delete('enrollment');
      return true;
    });
  }

  async prepareHost(token: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential()) return null;
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
    if (!setupAuthorized(this.env, token) || !await this.#credential()) return false;
    return (await this.env.HOST_PROBE?.startDeviceLogin().catch(() => false)) ?? false;
  }

  async configureTailnet(token: unknown, clientId: unknown, clientSecret: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential() ||
        typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/u.test(clientId) ||
        typeof clientSecret !== 'string' || !/^[\x21-\x7e]{16,256}$/u.test(clientSecret)) return false;
    return (await this.env.HOST_PROBE?.configureTailnet(clientId, clientSecret).catch(() => false)) ?? false;
  }

  async removeHost(token: unknown, address: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential() ||
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

  async beginPairing(token: unknown, address: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential() ||
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
    const callbackToken = crypto.randomUUID() + crypto.randomUUID();
    const id = crypto.randomUUID();
    const pairing = await this.ctx.storage.transaction(async tx => {
      const slot = 'pairing-address:' + address;
      const previousId = await tx.get<string>(slot);
      const previous = previousId ? await tx.get<Pairing>('pairing:' + previousId) : undefined;
      if (previous?.fingerprint) return previous;
      if (previousId) await tx.delete('pairing:' + previousId);
      const next = { id, address, account: maintenanceAccount, tokenHash: hashToken(callbackToken), expires: Date.now() + pairingLifetime };
      await tx.put('pairing:' + id, next);
      await tx.put(slot, id);
      return next;
    });
    if (!pairing) return null;
    if (pairing.fingerprint) return { id: pairing.id };
    const url = new URL('/setup', passkeyOrigin(this.env));
    url.searchParams.set('pair', id);
    return {
      id,
      download: { url: url.href, token: callbackToken },
      installCommand: 'curl -fsS -H ' + shellQuote('Authorization: Bearer ' + callbackToken) +
        ' ' + shellQuote(url.href) + ' | sudo sh',
    };
  }

  async pairingScript(id: string | null, token: string) {
    if (!id || !uuid.test(id) || !/^[0-9a-f-]{72}$/u.test(token)) return null;
    const pair = await this.ctx.storage.get<Pairing>('pairing:' + id);
    if (!pair || !pair.tokenHash || pair.fingerprint || pair.expires <= Date.now() ||
        !timingSafeEqual(Buffer.from(pair.tokenHash), Buffer.from(hashToken(token)))) return null;
    const account = pair.account ?? legacyAccount;
    const install = await this.env.HOST_PROBE?.prepareHostKey(pair.address, account).catch(() => null);
    if (!install) return null;
    const url = new URL(prefix + '/host-pairing', passkeyOrigin(this.env));
    url.searchParams.set('pair', id);
    const callback = 'curl -fsS -H ' + shellQuote('Authorization: Bearer ' + token);
    return [
      '#!/bin/sh',
      'cancel_pairing() {',
      '  ' + callback + ' --data-urlencode "account_action=canceled" ' + shellQuote(url.href),
      '}',
      'pair_host() {',
      '  PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin; export PATH',
      '  if [ "$(uname -s)" != Linux ]; then',
      "    echo 'Run this command on the selected Linux host, in its terminal or over SSH.' >&2; return 1",
      '  fi',
      '  if [ "$(id -u)" != 0 ]; then',
      "    echo 'Administrator permission is required. Copy the complete command from setup.' >&2; return 1",
      '  fi',
      '  if ! tailscale ip -4 | grep -Fxq -- ' + shellQuote(pair.address) + '; then',
      "    echo 'This machine is not the selected Tailscale host. Run the command on the selected machine.' >&2; return 1",
      '  fi',
      '  fingerprint=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk \'{print $2}\')',
      '  case "$fingerprint" in SHA256:*) ;; *)',
      "    echo 'No SSH host key found. Enable OpenSSH Server on this machine, then run the command again.' >&2; return 1;;",
      '  esac',
      '  account=' + shellQuote(account),
      '  if ! (true </dev/tty) 2>/dev/null; then',
      "    echo 'Run the installer in an interactive terminal on the selected host.' >&2; return 1",
      '  fi',
      '  if account_uid=$(id -u "$account" 2>/dev/null); then',
      '    if [ "$account_uid" = 0 ]; then',
      "      echo 'The dedicated account must be unprivileged.' >&2; return 1",
      '    fi',
      '    printf "1) Use the existing %s account and install its restricted key\n2) Cancel\nChoice [2]: " "$account" >/dev/tty',
      '    IFS= read -r answer </dev/tty || return 1',
      '    if [ "$answer" != 1 ]; then cancel_pairing; return 1; fi',
      '    account_action=reused',
      '  else',
      '    printf "1) Create the dedicated %s account and install its restricted key\n2) Cancel\nChoice [2]: " "$account" >/dev/tty',
      '    IFS= read -r answer </dev/tty || return 1',
      '    if [ "$answer" != 1 ]; then cancel_pairing; return 1; fi',
      '    useradd --system --create-home --home-dir /var/lib/"$account" --shell /bin/sh "$account" || return 1',
      '    account_action=created',
      '  fi',
      '  runuser -u "$account" -- /bin/sh -c ' + shellQuote(install) + ' &&',
      '  ' + callback + ' --data-urlencode "fingerprint=$fingerprint" --data-urlencode "account_action=$account_action" ' + shellQuote(url.href),
      '}',
      'pair_host',
      '',
    ].join('\n');
  }

  async cancelPairing(token: unknown, id: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential() ||
        typeof id !== 'string' || !uuid.test(id)) return null;
    return this.ctx.storage.transaction(async tx => {
      const slot = 'pairing:' + id;
      const pair = await tx.get<Pairing>(slot);
      if (!pair) return { state: 'invalidated' };
      if (pair.fingerprint) return { state: 'already_paired' };
      const addressSlot = 'pairing-address:' + pair.address;
      if (await tx.get<string>(addressSlot) === id) await tx.delete(addressSlot);
      await tx.delete(slot);
      return { state: 'invalidated' };
    });
  }

  async receiveFingerprint(id: string | null, callbackToken: string, fingerprint: unknown, accountAction: unknown) {
    if ((id !== null && !uuid.test(id)) || !/^[0-9a-f-]{72}$/u.test(callbackToken)) return false;
    const canceled = accountAction === 'canceled';
    const candidateFingerprint = typeof fingerprint === 'string' && /^SHA256:[A-Za-z0-9+/]{43}$/u.test(fingerprint)
      ? fingerprint : undefined;
    if (canceled ? fingerprint !== null : !candidateFingerprint) return false;
    return this.ctx.storage.transaction(async tx => {
      const slot = id === null ? 'pairing' : 'pairing:' + id;
      const pair = await tx.get<Pairing>(slot);
      if (!pair || pair.fingerprint || pair.expires <= Date.now() || pair.tokenHash !== hashToken(callbackToken)) return false;
      if (canceled) {
        await tx.put<Pairing>(slot, { ...pair, accountAction: 'canceled', tokenHash: '' });
        return true;
      }
      if (pair.account && accountAction !== 'created' && accountAction !== 'reused') return false;
      await tx.put<Pairing>(slot, {
        ...pair, fingerprint: candidateFingerprint, tokenHash: '',
        accountAction: accountAction === 'created' || accountAction === 'reused' ? accountAction : undefined,
      });
      return true;
    });
  }

  async finishPairing(token: unknown, id: unknown) {
    if (!setupAuthorized(this.env, token) || typeof id !== 'string') return null;
    const next = 'pairing:' + id;
    const slot = await this.ctx.storage.get<Pairing>(next) ? next : 'pairing';
    const pair = await this.ctx.storage.get<Pairing>(slot);
    if (pair?.id === id && pair.accountAction === 'canceled') return { state: 'pairing_canceled' };
    if (pair?.id !== id || (!pair.fingerprint && pair.expires <= Date.now())) return { state: 'pairing_expired' };
    if (!pair.fingerprint) return { state: 'waiting_for_host' };
    const finishing = this.#finishingPairings.get(id);
    if (finishing) return finishing;
    if (this.#changingHosts.has(pair.address)) return null;
    this.#changingHosts.add(pair.address);
    const operation = this.#finishPairing(pair, slot, id);
    this.#finishingPairings.set(id, operation);
    try {
      return await operation;
    } finally {
      this.#finishingPairings.delete(id);
      this.#changingHosts.delete(pair.address);
    }
  }

  async #finishPairing(pair: Pairing, slot: string, id: string) {
    const current = await this.ctx.storage.get<Pairing>(slot);
    if (current?.id !== id || !pair.fingerprint ||
        await this.ctx.storage.get('removing-host:' + pair.address)) return null;
    const legacy = await this.ctx.storage.get<Host>('onboarding-host');
    const host = {
      address: pair.address, fingerprint: pair.fingerprint, account: pair.account,
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

  async start(jobId: string, enrollment = false, address?: string, restart = false) {
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
    const target = host ? { ...hostCheck, host: host.address, fingerprint: host.fingerprint, execution_identity: host.account ?? legacyAccount, enrollmentId: host.enrollmentId, operation: restart ? restartOperation : hostCheck.operation } : diagnostic;
    const options = await generateAuthenticationOptions({
      rpID: origin.hostname, userVerification: 'required',
      allowCredentials: [{ id: credential.id, transports: credential.transports }],
    });
    const matches = await this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<Job>(key);
      if (existing) return existing.target.operation === target.operation &&
        existing.target.host === target.host && (target.dry_run || (!existing.target.dry_run &&
          existing.target.fingerprint === target.fingerprint && existing.target.execution_identity === target.execution_identity && existing.target.enrollmentId === target.enrollmentId));
      await tx.put<Job>(key, { target, options, expires_at: Date.now() + this.#jobLifetime() });
      return true;
    });
    if (!matches) return { state: 'job_id_in_use', ...empty };
    const status = await this.status(jobId);
    return status.state === 'pending'
      ? { ...status, review_url: new URL(prefix + '/review?job=' + jobId, origin).href }
      : status;
  }

  async status(jobId: string) {
    const job = await this.ctx.storage.get<Job>('job:' + jobId);
    if (!job) return { state: 'unknown', ...empty };
    const checkingState = job.approved_at &&
      (job.execution_owner !== this.#executionOwner || Date.now() >= job.approved_at + lifetime)
      ? 'check_outcome_unknown' : 'checking_host';
    const approvedState = job.target.dry_run ? 'verified_dry_run' : job.host_result?.state ?? job.host_verification ?? checkingState;
    const { host, operation, execution_identity, dry_run } = job.target;
    return {
      job_id: jobId, host, operation, execution_identity, dry_run,
      ...(!job.target.dry_run ? { fingerprint: job.target.fingerprint } : {}),
      ...(operation === restartOperation ? { service: restartUnit, run_as: 'root via a single sudo rule' } : {}), expires_at: job.expires_at,
      ...job.host_result,
      executed: job.host_result ? job.host_result.executed : (
        job.approved_at && !job.target.dry_run ? null : false
      ),
      state: job.approved_at ? approvedState : job.expires_at <= Date.now() ? 'expired' : 'pending',
      approved_at: job.approved_at ?? null,
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
    const accepted = await this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Job>(key);
      const stored = await tx.get<WebAuthnCredential>('credential');
      if (!current || current.approved_at || current.expires_at <= Date.now() ||
          stored?.id !== credential.id || stored.counter !== credential.counter) return false;
      await tx.put('credential', { ...credential, counter: verification.authenticationInfo.newCounter });
      await tx.put<Job>(key, { ...current, approved_at: Date.now(), execution_owner: this.#executionOwner });
      return true;
    });
    if (accepted && !job.target.dry_run) {
      const expected = {
        address: job.target.host, fingerprint: job.target.fingerprint, enrollmentId: job.target.enrollmentId, account: job.target.execution_identity,
      };
      this.ctx.waitUntil(this.#verifyHost(key, expected, job.target.operation));
    }
    return accepted;
  }

  async #verifyHost(key: string, expected: Host, operation: string) {
    let result: HostResult = { state: 'unconfigured', executed: false };
    const enrolled = await this.ctx.storage.get<Host>('onboarding-host:' + expected.address);
    const legacy = await this.ctx.storage.get<Host>('onboarding-host');
    const removing = await this.ctx.storage.get('removing-host:' + expected.address);
    if (removing || !sameEnrollmentHost(enrolled ?? legacy, expected)) {
      result = { state: 'target_changed', executed: false };
    } else if (this.env.HOST_PROBE && validEnrollmentHost(expected)) {
      result = await (operation === restartOperation ? this.env.HOST_PROBE.restartDemoService(expected)
        : this.env.HOST_PROBE.runHostEnrollmentCheck(expected)).catch(() => ({ state: 'check_outcome_unknown', executed: null }));
    }
    await this.ctx.storage.transaction(async tx => {
      const job = await tx.get<Job>(key);
      if (!job?.approved_at) return;
      await tx.put<Job>(key, { ...job, host_result: result });
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
  if (path === '/host-pairing') {
    const auth = request.headers.get('Authorization') ?? '';
    const mediaType = request.headers.get('Content-Type')?.split(';', 1)[0].trim();
    if (!auth.startsWith('Bearer ') || Number(length) > 1024 ||
        mediaType !== 'application/x-www-form-urlencoded') return reject(403);
    const form = new URLSearchParams(await request.text());
    return await store.receiveFingerprint(url.searchParams.get('pair'), auth.slice(7), form.get('fingerprint'), form.get('account_action'))
      ? new Response(form.get('account_action') === 'canceled' ? 'Pairing canceled.\n' : 'Host fingerprint received.\n', { headers })
      : reject(403);
  }
  if (request.headers.get('Origin') !== origin.origin) return reject(403);
  if (request.headers.get('Content-Type') !== 'application/json') return reject(415);
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return reject(400);
  const reply = (data: unknown) => Response.json(data, { headers });
  if (path === '/setup-state') {
    const setup = await store.setupState(body.token);
    return setup ? reply(setup) : reject(403);
  }
  if (path === '/enrollment-options') {
    const options = await store.enrollmentOptions(body.token);
    return options ? reply(options) : reject(403);
  }
  if (path === '/enroll') {
    return await store.enroll(body.token, body.response as RegistrationResponseJSON) ? reply({ enrolled: true }) : reject(403);
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
    const pair = await store.beginPairing(body.token, body.address);
    return pair ? reply(pair) : reject(403);
  }
  if (path === '/cancel-pairing') {
    const result = await store.cancelPairing(body.token, body.id);
    return result ? reply(result) : reject(403);
  }
  if (path === '/finish-host-pairing') {
    const result = await store.finishPairing(body.token, body.id);
    return result ? reply(result) : reject(403);
  }
  if (typeof body.job !== 'string' || !uuid.test(body.job)) return reject(400);
  if (path === '/review-options') {
    const options = await store.reviewOptions(body.job);
    return options ? reply({ options, job: await store.status(body.job) }) : reject(409);
  }
  if (path === '/approve') {
    return await store.approve(body.job, body.response as AuthenticationResponseJSON)
      ? reply(await store.status(body.job)) : reject(409);
  }
  if (path === '/job-status') return reply(await store.status(body.job));
  return reject(404);
}
