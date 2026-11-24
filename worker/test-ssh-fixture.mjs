import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import ssh2 from 'ssh2';
import {
  commandPrefix, enrollmentCommand, isHostAccount, legacyAccount, restartCommand, restartUnit, forcedCommand, generateSshKey, hostInstallCommand, mintTaggedAuthKey, sameEnrollmentHost, validEnrollmentHost,
} from '../experiments/tailnet/credentials.ts';

const directory = process.argv[2];
const approvalGate = fileURLToPath(new URL('../experiments/tailnet/host-approval.py', import.meta.url));
const approvalKeys = new Map();
const fixtureApproval = join(directory, 'fixture-approval.py');
writeFileSync(fixtureApproval, `
import os, re, runpy, sys
key, used, enrollment, host, account = (os.environ[name] for name in
    ("APPROVAL_KEY", "APPROVAL_USED", "APPROVAL_ENROLLMENT", "APPROVAL_HOST", "APPROVAL_ACCOUNT"))
try:
    consume = runpy.run_path(os.environ["APPROVAL_GATE"])["consume"]
    command = consume(sys.stdin.read(24001), key, used, enrollment=enrollment, host=host, account=account)
except (OSError, ValueError, KeyError):
    sys.exit(126)
if not re.fullmatch(r"printf '%s' 'pasta-dynamic-[a-f0-9-]+'(?:; exit 7)?", command):
    sys.exit(126)
os.execl("/bin/bash", "bash", "--noprofile", "--norc", "-c", command)
`);
function generate(name) {
  const key = join(directory, name);
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key]);
  const [, publicKey] = readFileSync(key + '.pub', 'utf8').split(' ');
  return { privateKey: readFileSync(key, 'utf8'), publicKey: Buffer.from(publicKey, 'base64') };
}
const host = generate('ssh-host');
const client = await generateSshKey();
const alternateClient = await generateSshKey();
const clientKeys = new Map([['100.64.0.2', client], ['100.64.0.3', alternateClient]]);
const installCommand = hostInstallCommand(client.publicKey);
const forcedLine = installCommand.split('\n').find(line => line.includes('restrict,command='));
assert.match(forcedLine, /restrict,command=/);
assert.ok(!installCommand.includes('PRIVATE KEY'));
const actualForcedCommand = forcedLine.match(/command="((?:\\.|[^"])*)"/u)[1].replace(/\\(["\\])/gu, '$1');
assert.equal(actualForcedCommand, forcedCommand);
const fakeSudo = join(directory, 'fixture-sudo');
const restartLog = join(directory, 'restarts');
writeFileSync(fakeSudo, '#!/bin/sh\n' +
  'test "$#" = 5 && test "$1" = -n && test "$2" = -- && ' +
  'test "$3" = /usr/bin/systemctl && test "$4" = restart && test "$5" = ' + restartUnit + ' || exit 65\n' +
  'test "$FIXTURE_MODE" != restart-denied || exit 1\n' +
  'echo restarted >> "$RESTART_LOG"\n', { mode: 0o700 });
const fixtureForcedCommand = actualForcedCommand.replace('/usr/bin/sudo', fakeSudo);
const dynamicLine = hostInstallCommand(client.publicKey, undefined, true).split('\n')
  .find(line => line.includes('restrict,command='));
const dynamicGate = dynamicLine.match(/command="((?:\\.|[^"])*)"/u)[1].replace(/\\(["\\])/gu, '$1');

for (const request of ['', enrollmentCommand + ' extra', enrollmentCommand + '; id', restartCommand + ' ssh.service', restartCommand + '; id']) {
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
for (const account of ['maintenance-relay', legacyAccount, 'ops-admin']) {
  const previous = { address: '100.64.0.2', fingerprint: pinned, account };
  assert.ok(validEnrollmentHost(previous));
  assert.ok(hostInstallCommand(client.publicKey, account).includes('"${1:-' + account + '}"'));
  assert.ok(sameEnrollmentHost(previous, { ...previous }));
  assert.ok(!sameEnrollmentHost(previous, { ...previous, account: 'pasta-mcp' }));
}
const devices = [{ name: 'Example host', address: '100.64.0.2' }];
let mode = 'normal';
let attempts = 0;
const enrolled = new Map();
let tailnetConfigured = false;
let deviceLogin = false;
let automaticDiscovery = false;

const ssh = new ssh2.Server({ hostKeys: [host.privateKey] }, connection => {
  connection.on('error', () => {});
  let authenticatedAddress;
  connection.on('authentication', auth => {
    if (!isHostAccount(auth.username) || auth.method !== 'publickey') return auth.reject();
    const address = [...clientKeys].find(([, key]) =>
      auth.key.data.equals(ssh2.utils.parseKey(key.publicKey).getPublicSSH()))?.[0];
    if (!address || auth.username !== (enrolled.get(address)?.account ?? legacyAccount)) return auth.reject();
    const clientPublic = ssh2.utils.parseKey(clientKeys.get(address).publicKey);
    if (auth.signature && clientPublic.verify(auth.blob, auth.signature, auth.hashAlgo) !== true) {
      return auth.reject();
    }
    authenticatedAddress = address;
    auth.accept();
  });
  connection.on('session', accept => {
    accept().on('exec', (acceptCommand, _reject, info) => {
      attempts++;
      const stream = acceptCommand();
      const dynamic = info.command.startsWith(commandPrefix);
      const target = enrolled.get(authenticatedAddress);
      const key = approvalKeys.get(target?.enrollmentId);
      if (dynamic && (!target?.signedApproval || !key)) {
        stream.exit(126);
        stream.end();
        return;
      }
      const gate = dynamic
        ? dynamicGate.replace('/usr/bin/sudo -n -- /usr/bin/python3 -I /usr/local/libexec/pasta-approval.py',
          '/usr/bin/python3 -I ' + fixtureApproval)
        : fixtureForcedCommand;
      const result = spawnSync('/bin/sh', ['-c', gate], {
        env: { SSH_ORIGINAL_COMMAND: info.command, RESTART_LOG: restartLog, FIXTURE_MODE: mode,
          ...(dynamic ? { APPROVAL_KEY: key.publicKey, APPROVAL_USED: key.used,
            APPROVAL_ENROLLMENT: target.enrollmentId, APPROVAL_HOST: target.address,
            APPROVAL_ACCOUNT: target.account ?? legacyAccount, APPROVAL_GATE: approvalGate } : {}),
        },
      });
      stream.write(mode === 'wrong-response' ? 'unexpected\n' : result.stdout);
      stream.exit(result.status);
      stream.end();
    });
  });
});
await new Promise(resolve => ssh.listen(0, '127.0.0.1', resolve));
createServer(async (request, response) => {
  const url = new URL(request.url, 'http://localhost');
  const address = url.searchParams.get('address');
  const clientKey = clientKeys.get(address);
  const visible = automaticDiscovery ? [...devices, { name: 'Auto host', address: '100.64.0.4' },
    { name: 'Recovery host', address: '100.64.0.5' }] : devices;
  if (url.pathname === '/approval-key' && request.method === 'POST') {
    let body = '';
    for await (const chunk of request) body += chunk;
    const { enrollment, publicKey } = JSON.parse(body);
    const path = join(directory, enrollment);
    mkdirSync(path, { recursive: true });
    const key = join(path, 'public.pem');
    writeFileSync(key, publicKey);
    approvalKeys.set(enrollment, { publicKey: key, used: path });
    response.end('{}');
  } else if (url.pathname === '/install') {
    const key = clientKey ?? await generateSshKey();
    clientKeys.set(address, key);
    response.end(JSON.stringify(hostInstallCommand(key.publicKey, url.searchParams.get('account') ?? legacyAccount, url.searchParams.get('dynamic') === 'true')));
  } else if (url.pathname === '/fixture') {
    const target = enrolled.get(address);
    const fingerprint = mode === 'wrong-pin' ? 'SHA256:' + 'A'.repeat(43) : target?.fingerprint;
    response.setHeader('X-Fixture-Mode', mode);
    response.end(JSON.stringify({
      host: mode === 'changed-target' ? { ...target, address: '100.64.0.3' } : target,
      port: ssh.address().port, fingerprint, privateKey: clientKey?.privateKey, interrupt: mode === 'interrupted',
    }));
  } else if (request.url === '/start-device-login' && request.method === 'POST') {
    deviceLogin = !tailnetConfigured;
    response.end(JSON.stringify(deviceLogin));
  } else if (request.url === '/prepare' && deviceLogin) {
    const state = mode === 'device-approval'
      ? { state: 'tailnet_pending', needsDeviceApproval: true }
      : mode === 'device-connected' ? { state: 'connected', devices }
        : { state: 'tailnet_pending', loginUrl: 'https://login.tailscale.com/a/example' };
    response.end(JSON.stringify(state));
  } else if (request.url === '/prepare') {
    response.end(JSON.stringify(tailnetConfigured
      ? { state: 'connected', deviceTag: 'tag:openbot-probe', devices: visible }
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
  } else if (request.url === '/remove' && request.method === 'POST') {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      const target = JSON.parse(body);
      const current = enrolled.get(target.address);
      const removed = mode !== 'removal-unavailable' && (!current || sameEnrollmentHost(current, target));
      if (removed) {
        enrolled.delete(target.address);
        clientKeys.delete(target.address);
      }
      response.end(JSON.stringify(removed));
    });
  } else if (request.url === '/save' && request.method === 'POST') {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      const host = JSON.parse(body);
      const previous = enrolled.get(host.address);
      const saved = validEnrollmentHost(host) && (!previous || sameEnrollmentHost(previous, host));
      if (saved) enrolled.set(host.address, host);
      response.end(JSON.stringify(saved));
    });
  } else if (request.method === 'POST' && request.url.startsWith('/mode/')) {
    mode = request.url.slice('/mode/'.length);
    if (mode === 'reset-device-login') deviceLogin = false;
    if (mode === 'automatic-discovery') automaticDiscovery = true;
    response.end();
  } else {
    let restarts = 0;
    try { restarts = readFileSync(restartLog, 'utf8').trim().split('\n').length; } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    response.end(JSON.stringify({ attempts, pinned, restarts }));
  }
}).listen(8796, '127.0.0.1');
