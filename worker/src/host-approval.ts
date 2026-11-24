import { generateKeyPairSync, sign } from 'node:crypto';

const lifetimeSeconds = 30;

export function createHostApprovalKey() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function signHostApproval(privateKey: string, approval: {
  job: string;
  enrollment: string;
  host: string;
  account: string;
  command: string;
}, now = Date.now()) {
  const issued = Math.floor(now / 1000);
  const payload = Buffer.from(JSON.stringify({
    version: 1, ...approval, issued, expires: issued + lifetimeSeconds,
  }));
  return payload.toString('base64url') + '.' + sign(null, payload, privateKey).toString('base64url');
}
