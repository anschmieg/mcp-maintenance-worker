import { SshClient } from '@workeryard/undershell';
import { commandPrefix, enrollmentCommand, enrollmentMarker, restartCommand, restartMarker, type HostAccount } from './credentials';

type SshSocket = Parameters<typeof SshClient.connect>[0]['socket'];
type Credentials = { PROBE_SSH_KEY: string; PROBE_HOST_FINGERPRINT: string; username: HostAccount };

export async function withSsh<T>(socket: SshSocket, credentials: Credentials, action: (ssh: SshClient) => Promise<T>) {
  let hostKeyVerified = false;
  let ssh: SshClient | undefined;
  try {
    ssh = await SshClient.connect({
      socket,
      username: credentials.username,
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
    const command = await ssh.exec(enrollmentCommand, {
      signal: AbortSignal.timeout(5000),
      maxOutputBytes: 1024,
    });
    const response = command.stdout.replace(/\r?\n$/u, '');
    if (command.exitStatus === 0 && !command.truncated && response === enrollmentMarker) {
      return { state: 'verified', executed: true, stdout: response, exit_status: 0 };
    }
    return { state: 'diagnostic_failed', executed: null, exit_status: command.exitStatus };
  });
  if ('state' in result) return result;
  return { state: result.hostKeyVerified ? 'ssh_authentication_failed' : 'host_key_unverified', executed: false };
}

export async function runServiceRestart(socket: SshSocket, credentials: Credentials) {
  const result = await withSsh(socket, credentials, async ssh => {
    const command = await ssh.exec(restartCommand, {
      signal: AbortSignal.timeout(15000),
      maxOutputBytes: 1024,
    });
    if (command.exitStatus === 0 && !command.truncated && command.stdout.replace(/\r?\n$/u, '') === restartMarker) {
      return { state: 'service_restarted', executed: true, exit_status: 0, stdout: restartMarker };
    }
    return { state: 'restart_failed', executed: null, exit_status: command.exitStatus };
  });
  if ('state' in result) return result;
  return { state: result.hostKeyVerified ? 'ssh_authentication_failed' : 'host_key_unverified', executed: false };
}

export async function runCommand(socket: SshSocket, credentials: Credentials, command: string) {
  const result = await withSsh(socket, credentials, async ssh => {
    const response = await ssh.exec(commandPrefix + command, {
      signal: AbortSignal.timeout(15000),
      maxOutputBytes: 8192,
    });
    if (response.exitStatus == null) return { state: 'check_outcome_unknown', executed: null };
    return {
      state: response.exitStatus === 0 ? 'command_completed' : 'command_failed',
      executed: true, exit_status: response.exitStatus,
      stdout: response.stdout, stderr: response.stderr, truncated: response.truncated,
    };
  });
  if ('state' in result) return result;
  return { state: result.hostKeyVerified ? 'ssh_authentication_failed' : 'host_key_unverified', executed: false };
}
