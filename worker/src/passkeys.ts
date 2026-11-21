import { DurableObject } from 'cloudflare:workers';
import { createHash, timingSafeEqual } from 'node:crypto';
import {
  generateAuthenticationOptions, generateRegistrationOptions,
  verifyAuthenticationResponse, verifyRegistrationResponse,
  type AuthenticationResponseJSON, type RegistrationResponseJSON, type WebAuthnCredential,
} from '@simplewebauthn/server';
import browserBundle from './passkey-browser.txt';
import approvalPage from './passkey-page.html';

const lifetime = 5 * 60_000;
const prefix = '/passkeys';
const empty = { executed: false };
const diagnostic = { host: 'ams', operation: 'openbot-enrollment-check-v1', execution_identity: 'openbot-tailnet-probe', dry_run: true };
const hostCheck = { ...diagnostic, operation: 'run openbot-enrollment-check-v1 to verify SSH enrollment', dry_run: false };
type HostVerification = 'unconfigured' | 'host_key_unverified' | 'ssh_authentication_failed' | 'verified' | 'connection_failed';
type HostResult =
  | { state: 'verified'; executed: true; stdout: string; exit_status: 0 }
  | { state: 'unconfigured' | 'host_key_unverified' | 'ssh_authentication_failed'; executed: false }
  | { state: 'diagnostic_failed' | 'check_outcome_unknown'; executed: null; exit_status?: number | null };
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
type Job = {
  target: typeof diagnostic | typeof hostCheck;
  options: Awaited<ReturnType<typeof generateAuthenticationOptions>>;
  expires_at: number;
  approved_at?: number;
  execution_owner?: string;
  host_verification?: HostVerification;
  host_result?: HostResult;
};
type Enrollment = { challenge: string; expires: number };
export type PasskeyEnv = {
  PASSKEYS: DurableObjectNamespace<PasskeyApproval>;
  PASSKEY_ORIGIN?: string;
  PASSKEY_SETUP_TOKEN?: string;
  PASSKEY_LOCAL_TEST_JOB_TTL_MS?: string;
  HOST_PROBE?: {
    runAmsEnrollmentCheck(): Promise<HostResult>;
    prepareEnrollment(): Promise<{ state: string; installCommand?: string }>;
    saveEnrollmentHost(host: { address: string; fingerprint: string }): Promise<boolean>;
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

  #credential() { return this.ctx.storage.get<WebAuthnCredential>('credential'); }

  #jobLifetime() {
    const testLifetime = Number(this.env.PASSKEY_LOCAL_TEST_JOB_TTL_MS);
    return passkeyOrigin(this.env)?.protocol === 'http:' &&
      Number.isSafeInteger(testLifetime) && testLifetime > 0 && testLifetime < lifetime ? testLifetime : lifetime;
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
    if (!this.env.HOST_PROBE) return { state: 'unconfigured' };
    return this.env.HOST_PROBE.prepareEnrollment().catch(() => ({ state: 'probe_unavailable' }));
  }

  async saveHost(token: unknown, address: unknown, fingerprint: unknown) {
    if (!setupAuthorized(this.env, token) || !await this.#credential() ||
        typeof address !== 'string' || typeof fingerprint !== 'string') return false;
    return (await this.env.HOST_PROBE?.saveEnrollmentHost({ address, fingerprint }).catch(() => false)) ?? false;
  }

  async start(jobId: string, enrollment = false) {
    const origin = passkeyOrigin(this.env)!;
    const credential = await this.#credential();
    if (!credential) return { state: 'enrollment_required', ...empty };
    const key = 'job:' + jobId;
    const target = enrollment ? hostCheck : diagnostic;
    const options = await generateAuthenticationOptions({
      rpID: origin.hostname, userVerification: 'required',
      allowCredentials: [{ id: credential.id, transports: credential.transports }],
    });
    const matches = await this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<Job>(key);
      if (existing) return existing.target.operation === target.operation;
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
    return {
      job_id: jobId, ...job.target, expires_at: job.expires_at,
      ...job.host_result,
      executed: job.host_result ? job.host_result.executed : (
        job.approved_at && job.target.operation === hostCheck.operation ? null : false
      ),
      state: job.approved_at ? approvedState : job.expires_at <= Date.now() ? 'expired' : 'pending',
      approved_at: job.approved_at ?? null,
    };
  }

  async hostStatus() {
    const latest = await this.ctx.storage.get<string>('last-completed-host-check');
    if (latest) return this.status(latest);
    return { host: hostCheck.host, state: this.env.HOST_PROBE ? 'awaiting_check' : 'unconfigured', ...empty };
  }

  async reviewOptions(jobId: string) {
    const job = await this.ctx.storage.get<Job>('job:' + jobId);
    if (!job || job.approved_at || job.expires_at <= Date.now() ||
        (!job.target.dry_run && job.target.operation !== hostCheck.operation)) return null;
    return job.options;
  }

  async approve(jobId: string, response: AuthenticationResponseJSON) {
    const origin = passkeyOrigin(this.env)!;
    const key = 'job:' + jobId;
    const job = await this.ctx.storage.get<Job>(key);
    const credential = await this.#credential();
    if (!credential || !job || job.approved_at || job.expires_at <= Date.now() ||
        (!job.target.dry_run && job.target.operation !== hostCheck.operation)) return false;
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
    if (accepted && job.target.operation === hostCheck.operation) this.ctx.waitUntil(this.#verifyHost(key));
    return accepted;
  }

  async #verifyHost(key: string) {
    const result: HostResult = this.env.HOST_PROBE
      ? await this.env.HOST_PROBE.runAmsEnrollmentCheck().catch(() => ({ state: 'check_outcome_unknown', executed: null }))
      : { state: 'unconfigured', executed: false };
    await this.ctx.storage.transaction(async tx => {
      const job = await tx.get<Job>(key);
      if (!job?.approved_at) return;
      await tx.put<Job>(key, { ...job, host_result: result });
      const previous = await tx.get<string>('last-completed-host-check');
      const previousJob = previous ? await tx.get<Job>('job:' + previous) : undefined;
      if (!previousJob?.approved_at || previousJob.approved_at <= job.approved_at) {
        await tx.put('last-completed-host-check', key.slice('job:'.length));
      }
    });
  }
}

export const approvalStore = (env: PasskeyEnv) => env.PASSKEYS.getByName('owner-v1');

const headers = {
  'Cache-Control': 'no-store',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
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
    if (path === '/onboard' || path === '/review') {
      return new Response(approvalPage, { headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' } });
    }
    if (path === '/browser.js') {
      return new Response(browserBundle, { headers: { ...headers, 'Content-Type': 'text/javascript; charset=utf-8' } });
    }
    return reject(404);
  }
  if (request.method !== 'POST') return reject(405);
  if (request.headers.get('Origin') !== origin.origin) return reject(403);
  const length = request.headers.get('Content-Length');
  if (!length || !/^\d{1,6}$/.test(length) || Number(length) > 32768) return reject(413);
  if (request.headers.get('Content-Type') !== 'application/json') return reject(415);
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || typeof body !== 'object' || Array.isArray(body)) return reject(400);
  const reply = (data: unknown) => Response.json(data, { headers });
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
  if (path === '/save-host') {
    const saved = await store.saveHost(body.token, body.address, body.fingerprint);
    return saved ? reply(await store.start(crypto.randomUUID(), true)) : reject(403);
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
