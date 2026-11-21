import { WorkerEntrypoint } from 'cloudflare:workers';
import { connect } from 'cloudflare:sockets';
import { sameEnrollmentHost, type Host } from '../experiments/tailnet/credentials';
import { runEnrollmentCheck, runServiceRestart } from '../experiments/tailnet/ssh-check';

export class HostVerifier extends WorkerEntrypoint {
  async configureTailnet(clientId: string, clientSecret: string) {
    const response = await fetch('http://127.0.0.1:8796/oauth', {
      method: 'POST', body: JSON.stringify({ clientId, clientSecret }),
    });
    return response.json();
  }

  async startDeviceLogin() {
    return (await fetch('http://127.0.0.1:8796/start-device-login', { method: 'POST' })).json();
  }

  async prepareEnrollment() {
    return (await fetch('http://127.0.0.1:8796/prepare')).json();
  }

  async prepareHostKey(address: string) {
    return (await fetch('http://127.0.0.1:8796/install?address=' + encodeURIComponent(address))).json();
  }

  async saveEnrollmentHost(host: { address: string; fingerprint: string }) {
    return (await fetch('http://127.0.0.1:8796/save', { method: 'POST', body: JSON.stringify(host) })).json();
  }

  async removeEnrollmentHost(expected: Host) {
    return (await fetch('http://127.0.0.1:8796/remove', { method: 'POST', body: JSON.stringify(expected) })).json();
  }

  async runHostEnrollmentCheck(expected: Host) {
    return this.#runHostAction(expected, runEnrollmentCheck);
  }

  async restartDemoService(expected: Host) {
    return this.#runHostAction(expected, runServiceRestart);
  }

  async #runHostAction(expected: Host, execute: typeof runEnrollmentCheck | typeof runServiceRestart) {
    const response = await fetch('http://127.0.0.1:8796/fixture?address=' + encodeURIComponent(expected.address));
    const { port, host, fingerprint, privateKey, interrupt } = await response.json();
    if (!sameEnrollmentHost(host, expected)) return { state: 'target_changed', executed: false };
    const socket = connect({ hostname: '127.0.0.1', port });
    const report = await execute({
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
