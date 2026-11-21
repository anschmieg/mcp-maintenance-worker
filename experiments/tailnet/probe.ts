import { TailnetObject, Tailnet } from './src/index.js';
import { runEnrollmentCheck } from './ssh-check';
import { generateSshKey, mintTaggedAuthKey, oauthConfigured, hostInstallCommand, validEnrollmentHost, type Host } from './credentials';
import { WorkerEntrypoint } from 'cloudflare:workers';

type Key = Awaited<ReturnType<typeof generateSshKey>>;

export class HostVerifier extends WorkerEntrypoint {
  #node() { return this.env.NODE.getByName('ams-probe'); }

  async prepareEnrollment() {
    if (!oauthConfigured(this.env) && !this.env.TS_AUTHKEY) return { state: 'unconfigured' };
    return this.#node().prepareEnrollment();
  }

  async saveEnrollmentHost(host: Host) {
    return this.#node().saveEnrollmentHost(host);
  }

  async runAmsEnrollmentCheck() {
    return this.#node().runEnrollmentCheck();
  }
}

export class ProbeNode extends TailnetObject {
  #starting?: Promise<Tailnet>;

  async tailnet() {
    this.#starting ??= this.#startTailnet();
    try {
      return await this.#starting;
    } catch (error) {
      this.#starting = undefined;
      throw error;
    }
  }

  async #startTailnet() {
    const tagged = oauthConfigured(this.env);
    const joined = await this.ctx.storage.get<boolean>('oauth-node-joined');
    const authKey = tagged ? (joined ? undefined : await mintTaggedAuthKey(this.env)) : this.env.TS_AUTHKEY;
    if (!tagged && !authKey) throw new Error('Tailscale enrollment is not configured');
    const node = await Tailnet.start(this.ctx, {
      hostname: 'openbot-tailnet-ssh-probe', authKey, ephemeral: !tagged,
      tags: tagged ? [this.env.TS_DEVICE_TAG] : [],
      statePrefix: tagged ? 'tailnet:tagged-v1:' : 'tailnet:',
    });
    return node;
  }

  async #readyTailnet() {
    const tailnet = await this.tailnet();
    await tailnet.ready(8000);
    if (oauthConfigured(this.env)) await this.ctx.storage.put('oauth-node-joined', true);
    return tailnet;
  }

  async prepareEnrollment() {
    const candidate = await generateSshKey();
    const key = await this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<Key>('enrollment-ssh-key');
      if (existing) return existing;
      await tx.put('enrollment-ssh-key', candidate);
      return candidate;
    });
    const connected = await this.#readyTailnet().then(() => true, () => false);
    return { state: connected ? 'connected' : 'tailnet_pending', installCommand: hostInstallCommand(key.publicKey) };
  }

  async saveEnrollmentHost(host: Host) {
    if (!validEnrollmentHost(host)) return false;
    return this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Host>('enrollment-host');
      if (current) return current.address === host.address && current.fingerprint === host.fingerprint;
      if (!await tx.get('enrollment-ssh-key')) return false;
      await tx.put('enrollment-host', host);
      return true;
    });
  }

  async runEnrollmentCheck() {
    const host = await this.ctx.storage.get<Host>('enrollment-host');
    const key = await this.ctx.storage.get<Key>('enrollment-ssh-key');
    if (!host || !key) return { state: 'unconfigured', executed: false };
    const tailnet = await this.#readyTailnet();
    return runEnrollmentCheck(await tailnet.connect(host.address + ':22'), {
      PROBE_SSH_KEY: key.privateKey, PROBE_HOST_FINGERPRINT: host.fingerprint,
    });
  }
}

export default { fetch: () => new Response(null, { status: 404 }) };
