import { TailnetObject, Tailnet } from './src/index.js';
import { runCommand, runEnrollmentCheck, runServiceRestart } from './ssh-check';
import { generateSshKey, mintTaggedAuthKey, oauthConfigured, hostInstallCommand, validEnrollmentHost, sameEnrollmentHost, validTailnetIpv4, guidedTag, legacyAccount, isHostAccount, tailnetHostname, type HostAccount, type Host, type TailnetDevice } from './credentials';
import { WorkerEntrypoint } from 'cloudflare:workers';

const keySlot = (address: string, dynamic?: boolean) =>
  (dynamic ? 'command-ssh-key:' : 'enrollment-ssh-key:') + address;

type Key = Awaited<ReturnType<typeof generateSshKey>>;
type GuidedJoin = { authKey?: string };

function tailscaleLoginUrl(value: unknown) {
  if (typeof value !== 'string') return;
  try {
    const url = new URL(value);
    if (url.origin === 'https://login.tailscale.com' && url.pathname.startsWith('/a/') &&
        !url.username && !url.password) return url.href;
  } catch { /* Ignore malformed login URLs. */ }
}

function visibleDevices(value: unknown): TailnetDevice[] {
  if (!Array.isArray(value)) return [];
  return value.filter(device => device && typeof device.name === 'string' &&
    typeof device.address === 'string' && validTailnetIpv4(device.address))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export class HostVerifier extends WorkerEntrypoint {
  #node() { return this.env.NODE.getByName('ams-probe'); }

  async prepareEnrollment() {
    return this.#node().prepareEnrollment();
  }

  async startDeviceLogin() {
    return this.#node().startDeviceLogin();
  }

  async configureTailnet(clientId: string, clientSecret: string) {
    return this.#node().configureTailnet(clientId, clientSecret);
  }

  async prepareHostKey(address: string, account: HostAccount = legacyAccount, commandExecution = false) {
    return this.#node().prepareHostKey(address, account, commandExecution);
  }

  async saveEnrollmentHost(host: Host) {
    return this.#node().saveEnrollmentHost(host);
  }

  async removeEnrollmentHost(expected: Host) {
    return this.#node().removeEnrollmentHost(expected);
  }

  async runHostEnrollmentCheck(expected: Host) {
    return this.#node().runHostAction(expected, 'check');
  }

  async runApprovedCommand(expected: Host, command: string) {
    return this.#node().runHostAction(expected, 'command', command);
  }

  async restartDemoService(expected: Host) {
    return this.#node().runHostAction(expected, 'restart');
  }
}

export class ProbeNode extends TailnetObject {
  #starting?: Promise<Tailnet>;
  #configuring?: Promise<boolean>;

  async startDeviceLogin() {
    if (oauthConfigured(this.env) || this.env.TS_AUTHKEY) return false;
    return this.ctx.storage.transaction(async tx => {
      if (await tx.get('guided-tailnet-join')) return false;
      await tx.put('interactive-tailnet-join', true);
      return true;
    });
  }

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
    if (oauthConfigured(this.env) || this.env.TS_AUTHKEY ||
        await this.ctx.storage.get('interactive-tailnet-join')) return false;
    const settings = {
      TS_OAUTH_CLIENT_ID: clientId, TS_OAUTH_CLIENT_SECRET: clientSecret, TS_DEVICE_TAG: guidedTag,
    };
    const authKey = await mintTaggedAuthKey(settings).catch(() => null);
    if (!authKey) return false;
    return this.ctx.storage.transaction(async tx => {
      if (await tx.get('interactive-tailnet-join')) return false;
      await tx.put('guided-tailnet-join', { authKey });
      await tx.delete('setup-inventory');
      return true;
    });
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
    const interactive = await this.ctx.storage.get<boolean>('interactive-tailnet-join');
    const guided = await this.ctx.storage.get<GuidedJoin>('guided-tailnet-join');
    const tagged = !interactive && oauthConfigured(this.env);
    const joined = await this.ctx.storage.get<boolean>('oauth-node-joined');
    const authKey = interactive ? undefined : guided ? guided.authKey
      : tagged ? (joined ? undefined : await mintTaggedAuthKey(this.env)) : this.env.TS_AUTHKEY;
    if (!interactive && !guided && !tagged && !authKey) throw new Error('Tailscale enrollment is not configured');
    const node = await Tailnet.start(this.ctx, {
      hostname: tailnetHostname, authKey, ephemeral: !interactive && !guided && !tagged,
      tags: guided ? [guidedTag] : tagged ? [this.env.TS_DEVICE_TAG] : [],
      statePrefix: interactive ? 'tailnet:interactive-v1:' : guided ? 'tailnet:guided-v1:' : tagged ? 'tailnet:tagged-v1:' : 'tailnet:',
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
    const interactive = await this.ctx.storage.get<boolean>('interactive-tailnet-join');
    const deviceTag = interactive ? undefined
      : guided ? guidedTag : oauthConfigured(this.env) ? this.env.TS_DEVICE_TAG : undefined;
    if (!interactive && !deviceTag && !this.env.TS_AUTHKEY) return { state: 'unconfigured' };
    const tailnet = interactive ? await this.tailnet() : null;
    const status = tailnet?.status();
    if (status && status.state !== 'Running') {
      return {
        state: 'tailnet_pending',
        loginUrl: status.state === 'NeedsLogin' ? tailscaleLoginUrl(status.loginURL) : undefined,
        needsDeviceApproval: status.state === 'NeedsMachineAuth',
      };
    }

    const ready = interactive ? tailnet : await this.#readyTailnet().catch(() => null);
    const connected = Boolean(ready);
    const running = ready?.status();
    const peers = visibleDevices(running?.visibleDevices);
    const probeAddress = Array.isArray(running?.addrs) ? running.addrs.find(validTailnetIpv4) : undefined;
    await this.ctx.storage.delete('setup-inventory');
    return {
      state: connected ? 'connected' : 'tailnet_pending', deviceTag,
      devices: peers, probeAddress,
    };
  }

  async prepareHostKey(address: string, account: HostAccount = legacyAccount, commandExecution = false) {
    if (!validTailnetIpv4(address) || !isHostAccount(account)) return null;
    const slot = keySlot(address, commandExecution);
    const existing = await this.ctx.storage.get<Key>(slot);
    if (existing) return hostInstallCommand(existing.publicKey, account, commandExecution);
    const candidate = await generateSshKey();
    const key = await this.ctx.storage.transaction(async tx => {
      const current = await tx.get<Key>(slot);
      if (current) return current;
      const legacy = await tx.get<Host>('enrollment-host');
      const selected = !commandExecution && legacy?.address === address ? await tx.get<Key>('enrollment-ssh-key') ?? candidate : candidate;
      await tx.put(slot, selected);
      return selected;
    });
    return hostInstallCommand(key.publicKey, account, commandExecution);
  }

  async saveEnrollmentHost(host: Host) {
    if (!validEnrollmentHost(host)) return false;
    return this.ctx.storage.transaction(async tx => {
      const slot = 'enrollment-host:' + host.address;
      const current = await tx.get<Host>(slot);
      const legacy = await tx.get<Host>('enrollment-host');
      if (current || legacy?.address === host.address) return sameEnrollmentHost(current ?? legacy, host);
      if (!await tx.get(keySlot(host.address, host.commandExecution))) return false;
      await tx.put(slot, host);
      return true;
    });
  }

  async removeEnrollmentHost(expected: Host) {
    if (!validEnrollmentHost(expected)) return false;
    const slot = 'enrollment-host:' + expected.address;
    return this.ctx.storage.transaction(async tx => {
      const legacy = await tx.get<Host>('enrollment-host');
      const current = await tx.get<Host>(slot) ?? (legacy?.address === expected.address ? legacy : undefined);
      if (current && !sameEnrollmentHost(current, expected)) return false;
      await tx.delete(slot);
      await tx.delete(keySlot(expected.address));
      await tx.delete(keySlot(expected.address, true));
      if (legacy?.address === expected.address) {
        await tx.delete('enrollment-host');
        await tx.delete('enrollment-ssh-key');
      }
      return true;
    });
  }

  async runHostAction(expected: Host, operation: 'check' | 'restart' | 'command', command?: string) {
    const { host, key } = await this.ctx.storage.transaction(async tx => {
      const legacy = await tx.get<Host>('enrollment-host');
      const legacyHost = legacy?.address === expected.address ? legacy : undefined;
      const host = await tx.get<Host>('enrollment-host:' + expected.address) ?? legacyHost;
      return {
        host,
        key: await tx.get<Key>(keySlot(expected.address, host?.commandExecution)) ??
          (legacyHost ? await tx.get<Key>('enrollment-ssh-key') : undefined),
      };
    });
    if (!host || !key) return { state: 'unconfigured', executed: false };
    if (!sameEnrollmentHost(host, expected)) return { state: 'target_changed', executed: false };
    if (operation === 'command' && (!host.commandExecution || !command)) return { state: 'unconfigured', executed: false };
    const tailnet = await this.#readyTailnet();
    const socket = await tailnet.connect(host.address + ':22');
    const credentials = {
      PROBE_SSH_KEY: key.privateKey, PROBE_HOST_FINGERPRINT: host.fingerprint, username: host.account ?? legacyAccount,
    };
    if (operation === 'command') return runCommand(socket, credentials, command!);
    return (operation === 'restart' ? runServiceRestart : runEnrollmentCheck)(socket, credentials);
  }
}

export default { fetch: () => new Response(null, { status: 404 }) };
