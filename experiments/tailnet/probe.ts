import { TailnetObject, Tailnet } from './src/index.js';
import { runEnrollmentCheck } from './ssh-check';
import { generateSshKey, mintTaggedAuthKey, listTailnetDevices, oauthConfigured, hostInstallCommand, validEnrollmentHost, guidedTag, type Host, type TailnetDevice } from './credentials';
import { WorkerEntrypoint } from 'cloudflare:workers';

type Key = Awaited<ReturnType<typeof generateSshKey>>;
type GuidedJoin = { authKey?: string };
type Inventory = { devices: TailnetDevice[]; expires: number };

export class HostVerifier extends WorkerEntrypoint {
  #node() { return this.env.NODE.getByName('ams-probe'); }

  async prepareEnrollment() {
    return this.#node().prepareEnrollment();
  }

  async configureTailnet(clientId: string, clientSecret: string) {
    return this.#node().configureTailnet(clientId, clientSecret);
  }

  async saveEnrollmentHost(host: Host) {
    return this.#node().saveEnrollmentHost(host);
  }

  async runHostEnrollmentCheck() {
    return this.#node().runEnrollmentCheck();
  }
}

export class ProbeNode extends TailnetObject {
  #starting?: Promise<Tailnet>;
  #configuring?: Promise<boolean>;

  async configureTailnet(clientId: string, clientSecret: string) {
    this.#configuring ??= this.#configureTailnet(clientId, clientSecret);
    try {
      return await this.#configuring;
    } finally {
      this.#configuring = undefined;
    }
  }

  async #configureTailnet(clientId: string, clientSecret: string) {
    if (await this.ctx.storage.get<GuidedJoin>('guided-tailnet-join')) return true;
    if (oauthConfigured(this.env) || this.env.TS_AUTHKEY) return false;
    const settings = {
      TS_OAUTH_CLIENT_ID: clientId, TS_OAUTH_CLIENT_SECRET: clientSecret, TS_DEVICE_TAG: guidedTag,
    };
    const [authKey, devices] = await Promise.all([
      mintTaggedAuthKey(settings).catch(() => null),
      listTailnetDevices(settings).catch(() => []),
    ]);
    if (!authKey) return false;
    await this.ctx.storage.put({
      'guided-tailnet-join': { authKey },
      'setup-inventory': { devices, expires: Date.now() + 15 * 60_000 },
    });
    return true;
  }

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
    const guided = await this.ctx.storage.get<GuidedJoin>('guided-tailnet-join');
    const tagged = oauthConfigured(this.env);
    const joined = await this.ctx.storage.get<boolean>('oauth-node-joined');
    const authKey = guided ? guided.authKey
      : tagged ? (joined ? undefined : await mintTaggedAuthKey(this.env)) : this.env.TS_AUTHKEY;
    if (!guided && !tagged && !authKey) throw new Error('Tailscale enrollment is not configured');
    const node = await Tailnet.start(this.ctx, {
      hostname: 'openbot-tailnet-ssh-probe', authKey, ephemeral: !guided && !tagged,
      tags: guided ? [guidedTag] : tagged ? [this.env.TS_DEVICE_TAG] : [],
      statePrefix: guided ? 'tailnet:guided-v1:' : tagged ? 'tailnet:tagged-v1:' : 'tailnet:',
    });
    return node;
  }

  async #readyTailnet() {
    const tailnet = await this.tailnet();
    await tailnet.ready(8000);
    const guided = await this.ctx.storage.get<GuidedJoin>('guided-tailnet-join');
    if (guided?.authKey) await this.ctx.storage.put<GuidedJoin>('guided-tailnet-join', {});
    if (oauthConfigured(this.env)) await this.ctx.storage.put('oauth-node-joined', true);
    return tailnet;
  }

  async prepareEnrollment() {
    const guided = await this.ctx.storage.get<GuidedJoin>('guided-tailnet-join');
    const deviceTag = guided ? guidedTag : oauthConfigured(this.env) ? this.env.TS_DEVICE_TAG : undefined;
    if (!deviceTag && !this.env.TS_AUTHKEY) return { state: 'unconfigured' };
    const candidate = await generateSshKey();
    const key = await this.ctx.storage.transaction(async tx => {
      const existing = await tx.get<Key>('enrollment-ssh-key');
      if (existing) return existing;
      await tx.put('enrollment-ssh-key', candidate);
      return candidate;
    });
    const connected = await this.#readyTailnet().then(() => true, () => false);
    const inventory = await this.ctx.storage.get<Inventory>('setup-inventory');
    if (inventory && inventory.expires <= Date.now()) await this.ctx.storage.delete('setup-inventory');
    return {
      state: connected ? 'connected' : 'tailnet_pending', installCommand: hostInstallCommand(key.publicKey), deviceTag,
      devices: inventory && inventory.expires > Date.now() ? inventory.devices : [],
    };
  }

  async saveEnrollmentHost(host: Host) {
    if (!validEnrollmentHost(host)) return false;
    return this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Host>('enrollment-host');
      if (current) return current.address === host.address && current.fingerprint === host.fingerprint;
      if (!await tx.get('enrollment-ssh-key')) return false;
      await tx.put('enrollment-host', host);
      await tx.delete('setup-inventory');
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
