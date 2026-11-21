import { WorkerEntrypoint } from 'cloudflare:workers';
import { connect } from 'cloudflare:sockets';
import { runEnrollmentCheck } from '../experiments/tailnet/ssh-check';

export class HostVerifier extends WorkerEntrypoint {
  async prepareEnrollment() {
    return (await fetch('http://127.0.0.1:8796/prepare')).json();
  }

  async saveEnrollmentHost(host: { address: string; fingerprint: string }) {
    return (await fetch('http://127.0.0.1:8796/save', { method: 'POST', body: JSON.stringify(host) })).json();
  }

  async runAmsEnrollmentCheck() {
    const response = await fetch('http://127.0.0.1:8796/fixture');
    const { port, fingerprint, privateKey, interrupt } = await response.json();
    const socket = connect({ hostname: '127.0.0.1', port });
    const report = await runEnrollmentCheck({
      readable: socket.readable,
      writable: socket.writable,
      close: () => socket.close(),
    }, { PROBE_HOST_FINGERPRINT: fingerprint, PROBE_SSH_KEY: privateKey });
    if (interrupt) throw new Error('Test service stopped responding after execution');
    if (response.headers.get('X-Fixture-Mode') === 'hang') {
      await new Promise(resolve => setTimeout(resolve, 300_000));
    }
    return report;
  }
}

export default { fetch: () => new Response(null, { status: 404 }) };
