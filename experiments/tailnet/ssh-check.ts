import { SshClient } from '@workeryard/undershell';

type SshSocket = Parameters<typeof SshClient.connect>[0]['socket'];
type Credentials = { PROBE_SSH_KEY: string; PROBE_HOST_FINGERPRINT: string };

export async function withSsh<T>(socket: SshSocket, credentials: Credentials, action: (ssh: SshClient) => Promise<T>) {
  let hostKeyVerified = false;
  let ssh: SshClient | undefined;
  try {
    ssh = await SshClient.connect({
      socket,
      username: 'openbot-tailnet-probe',
      auth: { kind: 'privateKey', privateKey: credentials.PROBE_SSH_KEY },
      hostKeyFingerprint: credentials.PROBE_HOST_FINGERPRINT,
      verifyHostKey() {
        hostKeyVerified = true;
        return true;
      },
      timeoutMs: 5000,
    });
    return await action(ssh);
  } catch (error) {
    if (ssh) throw error;
    return { hostKeyVerified, authentication: 'not_accepted', executed: false };
  } finally {
    await ssh?.close().catch(() => {});
    await socket.close().catch(() => {});
  }
}

export async function runEnrollmentCheck(socket: SshSocket, credentials: Credentials) {
  const result = await withSsh(socket, credentials, async ssh => {
    const command = await ssh.exec('openbot-enrollment-check-v1', {
      signal: AbortSignal.timeout(5000),
      maxOutputBytes: 1024,
    });
    const response = command.stdout.replace(/\r?\n$/u, '');
    if (command.exitStatus === 0 && !command.truncated && response === 'openbot-host-ready-v1') {
      return { state: 'verified', executed: true, stdout: response, exit_status: 0 };
    }
    return { state: 'diagnostic_failed', executed: null, exit_status: command.exitStatus };
  });
  if ('state' in result) return result;
  return { state: result.hostKeyVerified ? 'ssh_authentication_failed' : 'host_key_unverified', executed: false };
}
