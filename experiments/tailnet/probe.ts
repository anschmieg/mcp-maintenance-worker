import { TailnetObject } from './src/index.js';
import { SshClient } from '@workeryard/undershell';

export class ProbeNode extends TailnetObject {
  tailnetOptions() {
    return {
      hostname: 'openbot-tailnet-ssh-probe',
      authKey: this.env.TS_AUTHKEY,
      ephemeral: true,
    };
  }

  async probe() {
    const tailnet = await this.tailnet();
    await tailnet.ready(8000);
    const socket = await tailnet.connect(this.env.PROBE_TARGET);
    let hostKeyVerified = false;
    try {
      const ssh = await SshClient.connect({
        socket,
        username: 'openbot-tailnet-probe',
        auth: { kind: 'privateKey', privateKey: this.env.PROBE_SSH_KEY },
        hostKeyFingerprint: this.env.PROBE_HOST_FINGERPRINT,
        verifyHostKey() {
          hostKeyVerified = true;
          return true;
        },
        timeoutMs: 5000,
      });
      await ssh.close();
      return { hostKeyVerified, authentication: 'unexpectedly_accepted', executed: false };
    } catch {
      return { hostKeyVerified, authentication: 'not_accepted', executed: false };
    } finally {
      await socket.close().catch(() => {});
    }
  }
}

export default {
  async fetch(request, env) {
    if (!env.PROBE_TOKEN || request.headers.get('Authorization') !== `Bearer ${env.PROBE_TOKEN}`) {
      return new Response('Unauthorized', { status: 401 });
    }
    if (!env.TS_AUTHKEY || !env.PROBE_SSH_KEY || !env.PROBE_TARGET || !env.PROBE_HOST_FINGERPRINT) {
      return Response.json({ state: 'awaiting_scoped_enrollment' });
    }

    const node = env.NODE.getByName('ams-probe');
    const path = new URL(request.url).pathname;
    if (path === '/status') {
      const { state } = await node.tailnetStatus();
      return Response.json({ state });
    }
    if (path === '/probe' && request.method === 'POST') return Response.json(await node.probe());
    return new Response('Not found', { status: 404 });
  },
};
