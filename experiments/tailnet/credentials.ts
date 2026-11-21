const api = 'https://api.tailscale.com/api/v2/';

export type OAuthSettings = { TS_OAUTH_CLIENT_ID?: string; TS_OAUTH_CLIENT_SECRET?: string; TS_DEVICE_TAG?: string };

export function oauthConfigured(env: OAuthSettings) {
  return Boolean(env.TS_OAUTH_CLIENT_ID && env.TS_OAUTH_CLIENT_SECRET &&
    /^tag:[a-z][a-z0-9-]*$/u.test(env.TS_DEVICE_TAG ?? ''));
}

export async function mintTaggedAuthKey(env: OAuthSettings, request = fetch) {
  if (!oauthConfigured(env)) throw new Error('Tagged Tailscale OAuth is not configured');
  const tag = env.TS_DEVICE_TAG!;
  const token = await request(api + 'oauth/token', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
    body: new URLSearchParams({
      grant_type: 'client_credentials', client_id: env.TS_OAUTH_CLIENT_ID!,
      client_secret: env.TS_OAUTH_CLIENT_SECRET!, scope: 'auth_keys', tags: tag,
    }),
  });
  if (!token.ok) throw new Error('Tailscale OAuth exchange failed');
  const { access_token } = await token.json() as { access_token?: string };
  if (!access_token) throw new Error('Tailscale OAuth returned no token');
  const result = await request(api + 'tailnet/-/keys', {
    method: 'POST',
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
    headers: { Authorization: 'Bearer ' + access_token, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      capabilities: { devices: { create: { ephemeral: false, reusable: false, preauthorized: false, tags: [tag] } } },
      expirySeconds: 600,
    }),
  });
  if (!result.ok) throw new Error('Tailscale enrollment key creation failed');
  const { key } = await result.json() as { key?: string };
  if (!key?.startsWith('tskey-auth-')) throw new Error('Tailscale returned no enrollment key');
  return key;
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
export const forcedCommand = '[ "$SSH_ORIGINAL_COMMAND" = ' + enrollmentCommand +
  ' ] || exit 126; echo ' + enrollmentMarker;

export function hostInstallCommand(publicKey: string) {
  if (!/^ssh-ed25519 [A-Za-z0-9+/]{68}$/u.test(publicKey)) throw new Error('Invalid enrollment public key');
  const escaped = forcedCommand.replace(/["\\]/gu, '\\$&');
  const line = 'restrict,command="' + escaped + '" ' + publicKey + ' openbot-maintenance-enrollment';
  return [
    'test "$(id -un)" = openbot-tailnet-probe && umask 077 && mkdir -p "$HOME/.ssh" &&',
    '  chmod 700 "$HOME/.ssh" && touch "$HOME/.ssh/authorized_keys" && chmod 600 "$HOME/.ssh/authorized_keys" &&',
    "  key='" + line + "' &&",
    '  (grep -qxF -- "$key" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$key" >> "$HOME/.ssh/authorized_keys") &&',
    '  ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub',
  ].join('\n');
}

export type Host = { address: string; fingerprint: string };

export function validEnrollmentHost(host: Host) {
  const octets = host.address.split('.');
  return octets.length === 4 &&
    octets.every(octet => /^(0|[1-9][0-9]{0,2})$/u.test(octet) && Number(octet) <= 255) &&
    octets[0] === '100' && Number(octets[1]) >= 64 && Number(octets[1]) <= 127 &&
    /^SHA256:[A-Za-z0-9+/]{43}$/u.test(host.fingerprint);
}
