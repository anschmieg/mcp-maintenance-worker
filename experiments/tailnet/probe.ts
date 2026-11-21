import { TailnetObject } from './src/index.js';
import { runEnrollmentCheck, withSsh } from './ssh-check';
import { WorkerEntrypoint } from 'cloudflare:workers';

export class HostVerifier extends WorkerEntrypoint {
  async runAmsEnrollmentCheck() {
    if (!this.env.TS_AUTHKEY || !this.env.PROBE_SSH_KEY || !this.env.PROBE_TARGET ||
        !/^SHA256:[A-Za-z0-9+/]{43}$/.test(this.env.PROBE_HOST_FINGERPRINT ?? '')) {
      return { state: 'unconfigured', executed: false };
    }
    return this.env.NODE.getByName('ams-probe').runEnrollmentCheck();
  }
}

export class ProbeNode extends TailnetObject {
  tailnetOptions() {
    return {
      hostname: 'openbot-tailnet-ssh-probe',
      authKey: this.env.TS_AUTHKEY,
      ephemeral: true,
    };
  }

  async probe() {
    return withSsh(await this.#socket(), this.env, async () => ({ hostKeyVerified: true, authentication: 'authenticated', executed: false }));
  }

  async runEnrollmentCheck() {
    return runEnrollmentCheck(await this.#socket(), this.env);
  }

  async #socket() {
    const tailnet = await this.tailnet();
    await tailnet.ready(8000);
    return tailnet.connect(this.env.PROBE_TARGET);
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
