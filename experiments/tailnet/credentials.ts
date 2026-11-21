const api = 'https://api.tailscale.com/api/v2/';
export const maintenanceAccount = 'maintenance-relay';
export const legacyAccount = 'openbot-tailnet-probe';
export const tailnetHostname = 'maintenance-relay';
export type HostAccount = typeof maintenanceAccount | typeof legacyAccount;

export const guidedTag = 'tag:openbot-probe';

export type OAuthSettings = { TS_OAUTH_CLIENT_ID?: string; TS_OAUTH_CLIENT_SECRET?: string; TS_DEVICE_TAG?: string };

export function oauthConfigured(env: OAuthSettings) {
  return Boolean(env.TS_OAUTH_CLIENT_ID && env.TS_OAUTH_CLIENT_SECRET &&
    /^tag:[a-z][a-z0-9-]*$/u.test(env.TS_DEVICE_TAG ?? ''));
}

async function accessToken(env: OAuthSettings, scope: string, request: typeof fetch, tags?: string) {
  const body = new URLSearchParams({
    grant_type: 'client_credentials', client_id: env.TS_OAUTH_CLIENT_ID!,
    client_secret: env.TS_OAUTH_CLIENT_SECRET!, scope,
  });
  if (tags) body.set('tags', tags);
  const token = await request(api + 'oauth/token', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
    body,
  });
  if (!token.ok) throw new Error('Tailscale OAuth exchange failed');
  const { access_token } = await token.json() as { access_token?: string };
  if (!access_token) throw new Error('Tailscale OAuth returned no token');
  return access_token;
}

export async function mintTaggedAuthKey(env: OAuthSettings, request = fetch) {
  if (!oauthConfigured(env)) throw new Error('Tagged Tailscale OAuth is not configured');
  const tag = env.TS_DEVICE_TAG!;
  const token = await accessToken(env, 'auth_keys', request, tag);
  const result = await request(api + 'tailnet/-/keys', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      capabilities: { devices: { create: { ephemeral: false, reusable: false, preauthorized: false, tags: [tag] } } },
      expirySeconds: 86_400,
    }),
  });
  if (!result.ok) throw new Error('Tailscale enrollment key creation failed');
  const { key } = await result.json() as { key?: string };
  if (!key?.startsWith('tskey-auth-')) throw new Error('Tailscale returned no enrollment key');
  return key;
}

export type TailnetDevice = { name: string; address: string };

export async function listTailnetDevices(env: OAuthSettings, request = fetch): Promise<TailnetDevice[]> {
  const token = await accessToken(env, 'devices:core:read', request);
  const result = await request(api + 'tailnet/-/devices', {
    redirect: 'error', signal: AbortSignal.timeout(5000), headers: { Authorization: 'Bearer ' + token },
  });
  if (!result.ok) throw new Error('Tailscale device listing failed');
  const { devices } = await result.json() as { devices?: Array<{ hostname?: string; addresses?: string[] }> };
  const choices = new Map<string, TailnetDevice>();
  for (const device of devices ?? []) {
    const address = device.addresses?.find(validTailnetIpv4);
    if (!address) continue;
    const name = typeof device.hostname === 'string' ? device.hostname.slice(0, 120) : address;
    choices.set(address, { name: name || address, address });
    if (choices.size === 100) break;
  }
  return [...choices.values()].sort((a, b) => a.name.localeCompare(b.name));
}

export async function generateSshKey() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const algorithm = new TextEncoder().encode('ssh-ed25519');
  const wire = new Uint8Array(8 + algorithm.length + raw.length);
  const lengths = new DataView(wire.buffer);
  lengths.setUint32(0, algorithm.length);
  wire.set(algorithm, 4);
  lengths.setUint32(4 + algorithm.length, raw.length);
  wire.set(raw, 8 + algorithm.length);
  return {
    publicKey: 'ssh-ed25519 ' + btoa(String.fromCharCode(...wire)),
    privateKey: '-----BEGIN PRIVATE KEY-----\n' + btoa(String.fromCharCode(...pkcs8)) + '\n-----END PRIVATE KEY-----',
  };
}

export const enrollmentCommand = 'openbot-enrollment-check-v1';
export const enrollmentMarker = 'openbot-host-ready-v1';
export const restartCommand = 'openbot-restart-demo-service-v1';
export const restartUnit = 'openbot-maintenance-demo.service';
export const restartMarker = 'openbot-service-restarted-v1';
export const forcedCommand =
  'case "$SSH_ORIGINAL_COMMAND" in ' +
  enrollmentCommand + ') echo ' + enrollmentMarker + ';; ' +
  restartCommand + ') /usr/bin/sudo -n -- /usr/bin/systemctl restart ' + restartUnit +
  ' && echo ' + restartMarker + ';; *) exit 126;; esac';

export function hostInstallCommand(publicKey: string, account: HostAccount = maintenanceAccount) {
  if (!/^ssh-ed25519 [A-Za-z0-9+/]{68}$/u.test(publicKey)) throw new Error('Invalid enrollment public key');
  if (account !== maintenanceAccount && account !== legacyAccount) throw new Error('Invalid maintenance account');
  const escaped = forcedCommand.replace(/["\\]/gu, '\\$&');
  const line = 'restrict,command="' + escaped + '" ' + publicKey + ' openbot-maintenance-enrollment';
  return [
    'test "$(id -un)" = ' + account + ' && umask 077 && mkdir -p "$HOME/.ssh" &&',
    '  chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" &&',
    "  key='" + line + "' &&",
    '  (grep -qxF -- "$key" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$key" >> "$HOME/.ssh/authorized_keys")',
  ].join('\n');
}

export type Host = { address: string; fingerprint: string; enrollmentId?: string; account?: HostAccount };

export function validTailnetIpv4(address: string) {
  if (typeof address !== 'string') return false;
  const octets = address.split('.');
  return octets.length === 4 &&
    octets.every(octet => /^(0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255) &&
    octets[0] === '100' && Number(octets[1]) >= 64 && Number(octets[1]) <= 127;
}

export function validEnrollmentHost(host: Host) {
  return (host.account === undefined || host.account === maintenanceAccount || host.account === legacyAccount) &&
    validTailnetIpv4(host.address) && /^SHA256:[A-Za-z0-9+/]{43}$/u.test(host.fingerprint);
}

export function sameEnrollmentHost(current: Host | undefined, expected: Host) {
  return current?.address === expected.address && current.fingerprint === expected.fingerprint &&
    current.enrollmentId === expected.enrollmentId &&
    (current.account ?? legacyAccount) === (expected.account ?? legacyAccount);
}
