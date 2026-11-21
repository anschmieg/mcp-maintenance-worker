import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import ssh2 from 'ssh2';
import {
  enrollmentCommand, forcedCommand, generateSshKey, hostInstallCommand, mintTaggedAuthKey, validEnrollmentHost,
} from '../experiments/tailnet/credentials.ts';

const directory = process.argv[2];
function generate(name) {
  const key = join(directory, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
  const [, publicKey] = readFileSync(key + '.pub', 'utf8').split(' ');
  return { privateKey: readFileSync(key, 'utf8'), publicKey: Buffer.from(publicKey, 'base64') };
}
const host = generate('ssh-host');
const client = await generateSshKey();
const clientPublic = ssh2.utils.parseKey(client.publicKey);
const installCommand = hostInstallCommand(client.publicKey);
const forcedLine = installCommand.split('\n').find(line => line.includes('restrict,command='));
assert.match(forcedLine, /restrict,command=/);
assert.ok(!installCommand.includes('PRIVATE KEY'));
const actualForcedCommand = forcedLine.match(/command="((?:\\.|[^"])*)"/u)[1].replace(/\\(["\\])/gu, '$1');
assert.equal(actualForcedCommand, forcedCommand);
for (const request of ['', enrollmentCommand + ' extra', enrollmentCommand + '; id']) {
  assert.throws(() => execFileSync('/bin/sh', ['-c', actualForcedCommand], {
    env: { SSH_ORIGINAL_COMMAND: request },
  }), error => error.status === 126);
}

const oauthRequests = [];
const enrollmentKey = await mintTaggedAuthKey({
  TS_OAUTH_CLIENT_ID: 'example-id', TS_OAUTH_CLIENT_SECRET: 'example-secret', TS_DEVICE_TAG: 'tag:openbot-probe',
}, async (url, options) => {
  oauthRequests.push({ url, options });
  return Response.json(oauthRequests.length === 1 ? { access_token: 'example-token' } : { key: 'tskey-auth-example' });
});
assert.equal(enrollmentKey, 'tskey-auth-example');
assert.equal(oauthRequests[0].options.body.get('scope'), 'auth_keys');
assert.equal(oauthRequests[0].options.body.get('tags'), 'tag:openbot-probe');
const keyRequest = JSON.parse(oauthRequests[1].options.body);
assert.equal(keyRequest.expirySeconds, 86_400);
assert.deepEqual(keyRequest.capabilities.devices.create, {
  ephemeral: false, reusable: false, preauthorized: false, tags: ['tag:openbot-probe'],
});
const pinned = 'SHA256:' + createHash('sha256').update(host.publicKey).digest('base64').replace(/=$/, '');
let mode = 'normal';
let attempts = 0;
let enrolled;
let tailnetConfigured = false;

const ssh = new ssh2.Server({ hostKeys: [host.privateKey] }, connection => {
  connection.on('error', () => {});
  connection.on('authentication', auth => {
    if (auth.username !== 'openbot-tailnet-probe' || auth.method !== 'publickey' ||
        !auth.key.data.equals(clientPublic.getPublicSSH())) return auth.reject();
    if (auth.signature && clientPublic.verify(auth.blob, auth.signature, auth.hashAlgo) !== true) {
      return auth.reject();
    }
    auth.accept();
  });
  connection.on('session', accept => {
    accept().on('exec', (acceptCommand, _reject, info) => {
      attempts++;
      const stream = acceptCommand();
      assert.equal(info.command, enrollmentCommand);
      const stdout = execFileSync('/bin/sh', ['-c', actualForcedCommand], { env: { SSH_ORIGINAL_COMMAND: info.command } });
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
  } else if (request.url === '/prepare') {
    response.end(JSON.stringify(tailnetConfigured
      ? { state: 'connected', installCommand, deviceTag: 'tag:openbot-probe' }
      : { state: 'unconfigured' }));
  } else if (request.url === '/oauth' && request.method === 'POST') {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      const { clientId, clientSecret } = JSON.parse(body);
      const accepted = clientId === 'test-id' && clientSecret === 'example-oauth-secret';
      if (accepted) tailnetConfigured = true;
      response.end(JSON.stringify(accepted));
    });
  } else if (request.url === '/save' && request.method === 'POST') {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      const host = JSON.parse(body);
      const saved = validEnrollmentHost(host) &&
        (!enrolled || (enrolled.address === host.address && enrolled.fingerprint === host.fingerprint));
      if (saved) enrolled = host;
      response.end(JSON.stringify(saved));
    });
  } else if (request.method === 'POST' && request.url.startsWith('/mode/')) {
    mode = request.url.slice('/mode/'.length);
    response.end();
  } else {
    response.end(JSON.stringify({ attempts }));
  }
}).listen(8796, '127.0.0.1');
