import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import ssh2 from 'ssh2';

const directory = process.argv[2];
function generate(name) {
  const key = join(directory, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
  const [, publicKey] = readFileSync(key + '.pub', 'utf8').split(' ');
  return { privateKey: readFileSync(key, 'utf8'), publicKey: Buffer.from(publicKey, 'base64') };
}
const host = generate('ssh-host');
const client = generate('ssh-client');
const pinned = 'SHA256:' + createHash('sha256').update(host.publicKey).digest('base64').replace(/=$/, '');
let mode = 'normal';
let attempts = 0;

const ssh = new ssh2.Server({ hostKeys: [host.privateKey] }, connection => {
  connection.on('error', () => {});
  connection.on('authentication', auth => {
    if (auth.username !== 'openbot-tailnet-probe' || auth.method !== 'publickey' ||
        !auth.key.data.equals(client.publicKey)) return auth.reject();
    if (auth.signature && ssh2.utils.parseKey(client.privateKey).verify(auth.blob, auth.signature, auth.hashAlgo) !== true) {
      return auth.reject();
    }
    auth.accept();
  });
  connection.on('session', accept => {
    accept().on('exec', (acceptCommand, _reject, info) => {
      attempts++;
      const stream = acceptCommand();
      assert.equal(info.command, 'openbot-enrollment-check-v1');
      const handler = fileURLToPath(new URL('../experiments/tailnet/openbot-enrollment-check', import.meta.url));
      const stdout = execFileSync('/bin/sh', [handler], { env: { SSH_ORIGINAL_COMMAND: info.command } });
      stream.write(mode === 'wrong-response' ? 'unexpected\n' : stdout);
      stream.exit(0);
      stream.end();
    });
  });
});
await new Promise(resolve => ssh.listen(0, '127.0.0.1', resolve));
createServer((request, response) => {
  if (request.url === '/fixture') {
    const fingerprint = mode === 'wrong-pin' ? 'SHA256:' + 'A'.repeat(43) : pinned;
    response.setHeader('X-Fixture-Mode', mode);
    response.end(JSON.stringify({
      port: ssh.address().port, fingerprint, privateKey: client.privateKey, interrupt: mode === 'interrupted',
    }));
  } else if (request.method === 'POST' && request.url.startsWith('/mode/')) {
    mode = request.url.slice('/mode/'.length);
    response.end();
  } else {
    response.end(JSON.stringify({ attempts }));
  }
}).listen(8796, '127.0.0.1');
