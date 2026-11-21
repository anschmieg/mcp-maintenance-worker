import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const { PASSKEY_ORIGIN: origin, PASSKEY_SETUP_TOKEN: setupToken, MCP_BEARER_TOKEN: mcpToken } = process.env;
assert.ok(origin && setupToken && mcpToken);
const rpId = new URL(origin).hostname;

async function post(path, body, requestOrigin = origin) {
  return fetch(origin + '/passkeys/' + path, {
    method: 'POST', headers: { Origin: requestOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function call(name, job_id, host) {
  const client = new Client({ name: 'passkey-integration-test', version: '1' });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL('/mcp', origin), {
      requestInit: { headers: { Authorization: 'Bearer ' + mcpToken } },
    }), { timeout: 8000 });
    const result = await client.callTool({ name, arguments: { ...(job_id ? { job_id } : {}), ...(host ? { host } : {}) } });
    assert.ok(!result.isError, JSON.stringify(result));
    assert.ok([false, true, null].includes(result.structuredContent.executed));
    return result.structuredContent;
  } finally { await client.close(); }
}

const fixture = 'http://127.0.0.1:8796';
const attempts = async () => (await (await fetch(fixture + '/attempts')).json()).attempts;
const receipt = process.argv[2];
if (process.argv[3] === 'after-restart') {
  const { hostJob, hostApproval, count } = JSON.parse(readFileSync(receipt, 'utf8'));
  const status = await call('passkey_test_status', hostJob);
  assert.equal(status.state, 'check_outcome_unknown');
  assert.equal(status.executed, null);
  assert.deepEqual(await call('start_host_enrollment', hostJob, status.host), status);
  assert.equal((await post('approve', { job: hostJob, response: hostApproval })).status, 409);
  assert.equal(await attempts(), count);
  console.log('PASS: Worker restart preserved the consumed approval without repeating SSH');
  process.exit(0);
}

const job = randomUUID();
assert.equal((await call('start_passkey_test', job)).state, 'enrollment_required');
assert.equal((await post('enrollment-options', { token: mcpToken })).status, 403);
assert.equal((await post('prepare-host', { token: setupToken })).status, 403);
assert.equal((await post('prepare-host', { token: mcpToken })).status, 403);
assert.equal((await post('enrollment-options', { token: setupToken }, 'https://other.example')).status, 403);
assert.equal((await fetch(origin + '/passkeys/onboard')).status, 200);
assert.match(await (await fetch(origin + '/passkeys/browser.js')).text(), /startRegistration/);

const hash = data => createHash('sha256').update(data).digest();
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const { x, y } = publicKey.export({ format: 'jwk' });
const cose = Buffer.from(encodeCBOR(new Map([
  [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(x, 'base64url')], [-3, Buffer.from(y, 'base64url')],
])));
const rawId = randomBytes(32);
const id = b64(rawId);
const identity = { id, rawId: id, type: 'public-key', clientExtensionResults: {} };
const clientData = (type, challenge, requestOrigin = origin) =>
  Buffer.from(JSON.stringify({ type, challenge, origin: requestOrigin }));
const authenticatorData = (flags) => Buffer.concat([hash(rpId), Buffer.of(flags), Buffer.alloc(4)]);
const setup = await post('enrollment-options', { token: setupToken });
assert.equal(setup.status, 200);
const enrollment = await setup.json();
const attestation = encodeCBOR(new Map([
  ['fmt', 'none'], ['attStmt', new Map()],
  ['authData', Buffer.concat([authenticatorData(0x45), Buffer.alloc(16), Buffer.of(0, rawId.length), rawId, cose])],
]));
const registration = {
  ...identity, response: {
    clientDataJSON: b64(clientData('webauthn.create', enrollment.challenge)),
    attestationObject: b64(attestation),
  },
};
assert.equal((await post('enroll', { token: setupToken, response: registration })).status, 200);
assert.equal((await post('enroll', { token: setupToken, response: registration })).status, 403);
assert.equal((await post('enrollment-options', { token: setupToken })).status, 403);
assert.equal((await post('prepare-host', { token: mcpToken })).status, 403);
assert.deepEqual(await (await post('prepare-host', { token: setupToken })).json(), { state: 'unconfigured' });
assert.equal((await post('start-device-login', { token: mcpToken })).status, 403);
assert.equal((await post('start-device-login', { token: setupToken }, 'https://other.example')).status, 403);
assert.deepEqual(await (await post('start-device-login', { token: setupToken })).json(), { started: true });
assert.deepEqual(await (await post('prepare-host', { token: setupToken })).json(), {
  state: 'tailnet_pending', loginUrl: 'https://login.tailscale.com/a/example',
});
assert.equal((await post('prepare-host', { token: mcpToken })).status, 403);
assert.equal((await post('begin-host-pairing', { token: setupToken, address: '100.64.0.2' })).status, 403);
await fetch(fixture + '/mode/device-approval', { method: 'POST' });
assert.deepEqual(await (await post('prepare-host', { token: setupToken })).json(), {
  state: 'tailnet_pending', needsDeviceApproval: true,
});
await fetch(fixture + '/mode/device-connected', { method: 'POST' });
const browserJoin = await (await post('prepare-host', { token: setupToken })).json();
assert.equal(browserJoin.state, 'connected');
assert.equal(browserJoin.loginUrl, undefined);
assert.deepEqual(browserJoin.devices, [{ name: 'Example host', address: '100.64.0.2' }]);
await fetch(fixture + '/mode/reset-device-login', { method: 'POST' });
const oauth = { clientId: 'test-id', clientSecret: 'example-oauth-secret' };
assert.equal((await post('configure-tailnet', { ...oauth, token: mcpToken })).status, 403);
assert.equal((await post('configure-tailnet', { ...oauth, token: setupToken }, 'https://other.example')).status, 403);
assert.equal((await post('configure-tailnet', {
  ...oauth, token: setupToken, clientSecret: 'wrong-example-secret',
})).status, 403);
assert.deepEqual(await (await post('configure-tailnet', { ...oauth, token: setupToken })).json(), { configured: true });
const setupResult = await (await post('prepare-host', { token: setupToken })).json();
assert.deepEqual(Object.keys(setupResult).sort(), ['deviceTag', 'devices', 'state']);
assert.equal(setupResult.deviceTag, 'tag:openbot-probe');
assert.equal(setupResult.state, 'connected');
assert.deepEqual(setupResult.devices, [{ name: 'Example host', address: '100.64.0.2' }]);
const address = setupResult.devices[0].address;
const { pinned: hostPin } = await (await fetch(fixture + '/attempts')).json();
assert.equal((await post('begin-host-pairing', { token: mcpToken, address })).status, 403);
assert.equal((await post('begin-host-pairing', { token: setupToken, address: '127.0.0.1' })).status, 403);
const pair = await (await post('begin-host-pairing', { token: setupToken, address })).json();
assert.match(pair.installCommand, /ssh-keygen.*ssh_host_ed25519_key.pub/u);
execFileSync('/bin/sh', ['-n', '-c', pair.installCommand]);
const callbackToken = pair.installCommand.match(/Authorization: Bearer ([0-9a-f-]{72})/u)[1];
function hostCallback(token, fingerprint, pairing = pair.id) {
  return fetch(origin + '/passkeys/host-pairing?pair=' + pairing, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token },
    body: new URLSearchParams({ fingerprint }),
  });
}
assert.equal((await hostCallback(mcpToken, hostPin)).status, 403);
assert.equal((await hostCallback(callbackToken, 'invalid')).status, 403);
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: pair.id })).json(),
  { state: 'waiting_for_host' });
assert.equal((await hostCallback(callbackToken, hostPin)).status, 200);
assert.equal((await hostCallback(callbackToken, hostPin)).status, 403);
assert.equal((await post('finish-host-pairing', { token: mcpToken, id: pair.id })).status, 403);
const hostSetup = await (await post('finish-host-pairing', { token: setupToken, id: pair.id })).json();
assert.equal(hostSetup.state, 'pending');
assert.equal(hostSetup.host, address);
assert.equal(hostSetup.fingerprint, hostPin);
assert.equal(hostSetup.executed, false);
assert.equal(await attempts(), 0);
console.log('PASS: owner device picker and one-time host callback pin the selected host before review');

const pending = await call('start_passkey_test', job);
assert.equal(pending.state, 'pending');
assert.equal((await fetch(pending.review_url)).status, 200);
assert.equal((await call('passkey_test_status', job)).state, 'pending');
const second = randomUUID();
await call('start_passkey_test', second);
const { options } = await (await post('review-options', { job })).json();
assert.equal(options.userVerification, 'required');

function assertion(flags, requestOrigin, challenge = options.challenge) {
  const authData = authenticatorData(flags);
  const data = clientData('webauthn.get', challenge, requestOrigin);
  return { ...identity, response: {
    authenticatorData: b64(authData),
    clientDataJSON: b64(data),
    signature: b64(sign('sha256', Buffer.concat([authData, hash(data)]), privateKey)),
  } };
}

const response = assertion(0x05);
assert.equal((await post('approve', { job, response: assertion(0x01) })).status, 409);
assert.equal((await post('approve', { job, response: assertion(0x05, 'https://other.example') })).status, 409);
assert.equal((await post('approve', { job: second, response })).status, 409);
const repeated = await Promise.all([post('approve', { job, response }), post('approve', { job, response })]);
assert.deepEqual(repeated.map(result => result.status).sort(), [200, 409]);
const approved = await call('passkey_test_status', job);
assert.equal(approved.state, 'verified_dry_run');
assert.ok(approved.approved_at);
assert.deepEqual(await call('start_passkey_test', job), approved);
assert.equal((await call('passkey_test_status', second)).state, 'pending');
console.log('PASS: passkey enrollment, origin and user verification, job binding, concurrent replay, and MCP reconnect');

assert.equal((await call('maintenance_host_status')).state, 'awaiting_check');
assert.equal((await call('start_host_enrollment', job)).state, 'job_id_in_use');
for (const [mode, state, executed, count] of [
  ['normal', 'verified', true, 1],
  ['wrong-pin', 'host_key_unverified', false, 1],
  ['changed-target', 'target_changed', false, 1],
  ['wrong-response', 'diagnostic_failed', null, 2],
  ['interrupted', 'check_outcome_unknown', null, 3],
]) {
  await fetch(fixture + '/mode/' + mode, { method: 'POST' });
  const hostJob = randomUUID();
  const hostRequest = await call('start_host_enrollment', hostJob);
  assert.equal(hostRequest.operation, 'run openbot-enrollment-check-v1 to verify SSH enrollment');
  assert.equal(hostRequest.state, 'pending');
  assert.equal(hostRequest.executed, false);
  assert.equal(await attempts(), count - (mode === 'wrong-pin' || mode === 'changed-target' ? 0 : 1));
  assert.equal((await post('approve', { job: hostJob, response })).status, 409);
  const hostReview = await (await post('review-options', { job: hostJob })).json();
  const hostApproval = assertion(0x05, origin, hostReview.options.challenge);
  const approval = await post('approve', { job: hostJob, response: hostApproval });
  assert.equal(approval.status, 200);
  assert.equal((await post('approve', { job: hostJob, response: hostApproval })).status, 409);
  let hostStatus;
  for (let retry = 0; retry < 60; retry++) {
    hostStatus = await call('passkey_test_status', hostJob);
    if (hostStatus.state !== 'checking_host') break;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.equal(hostStatus.state, state);
  assert.equal(hostStatus.executed, executed);
  if (executed) {
    assert.equal(hostStatus.stdout, 'openbot-host-ready-v1');
    assert.equal(hostStatus.exit_status, 0);
  }
  assert.deepEqual(await call('maintenance_host_status'), hostStatus);
  assert.deepEqual(await call('start_host_enrollment', hostJob), hostStatus);
  assert.equal(await attempts(), count);
  console.log('PASS: host enrollment ' + mode + ', status after reconnect, replay rejected');
}

const expiredJob = randomUUID();
const expiring = await call('start_host_enrollment', expiredJob);
const expiringReview = await (await post('review-options', { job: expiredJob })).json();
const expiredAssertion = assertion(0x05, origin, expiringReview.options.challenge);
const beforeExpiry = await attempts();
await new Promise(resolve => setTimeout(resolve, Math.max(0, expiring.expires_at - Date.now() + 100)));
assert.equal((await post('approve', { job: expiredJob, response: expiredAssertion })).status, 409);
assert.equal((await call('passkey_test_status', expiredJob)).state, 'expired');
assert.equal(await attempts(), beforeExpiry);
const [resumed, repeatedResume] = await Promise.all([
  post('finish-host-pairing', { token: setupToken, id: pair.id }).then(result => result.json()),
  post('finish-host-pairing', { token: setupToken, id: pair.id }).then(result => result.json()),
]);
assert.equal(resumed.state, 'pending');
assert.notEqual(resumed.job_id, hostSetup.job_id);
assert.equal(resumed.job_id, repeatedResume.job_id);
assert.equal(await attempts(), beforeExpiry);
console.log('PASS: expired approval did not open SSH');

await fetch(fixture + '/mode/normal', { method: 'POST' });
const alternateAddress = '100.64.0.3';
const alternatePair = await (await post('begin-host-pairing', { token: setupToken, address: alternateAddress })).json();
assert.notEqual(alternatePair.id, pair.id);
const installedPublicKey = command => command.match(/ssh-ed25519 [A-Za-z0-9+/]+/u)[0];
assert.notEqual(installedPublicKey(alternatePair.installCommand), installedPublicKey(pair.installCommand));
const alternateToken = alternatePair.installCommand.match(/Authorization: Bearer ([0-9a-f-]{72})/u)[1];
assert.equal((await hostCallback(alternateToken, hostPin, pair.id)).status, 403);
assert.equal((await hostCallback(alternateToken, hostPin, alternatePair.id)).status, 200);
const alternateSetup = await (await post('finish-host-pairing', { token: setupToken, id: alternatePair.id })).json();
assert.equal(alternateSetup.host, alternateAddress);
assert.deepEqual((await call('maintenance_hosts')).hosts, [{ address }, { address: alternateAddress }]);
assert.equal((await call('start_host_enrollment', randomUUID())).state, 'host_selection_required');
const alternateJob = randomUUID();
assert.equal((await call('start_host_enrollment', alternateJob, alternateAddress)).host, alternateAddress);
assert.equal((await call('start_host_enrollment', alternateJob, address)).state, 'job_id_in_use');
const alternateReview = await (await post('review-options', { job: alternateJob })).json();
assert.equal((await post('approve', {
  job: alternateJob, response: assertion(0x05, origin, alternateReview.options.challenge),
})).status, 200);
for (let retry = 0; retry < 60; retry++) {
  const current = await call('passkey_test_status', alternateJob);
  if (current.state === 'verified') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal((await call('passkey_test_status', alternateJob)).state, 'verified');
assert.equal((await call('maintenance_host_status', undefined, alternateAddress)).job_id, alternateJob);
assert.equal((await call('maintenance_host_status', undefined, address)).host, address);
assert.equal(await attempts(), beforeExpiry + 1);
console.log('PASS: two host targets use distinct client keys and isolated pairing and job IDs');

const staleJob = randomUUID();
const staleRequest = await call('start_host_enrollment', staleJob, alternateAddress);
assert.equal(staleRequest.state, 'pending');
const staleReview = await (await post('review-options', { job: staleJob })).json();
assert.equal((await post('remove-host', { token: mcpToken, address: alternateAddress })).status, 403);
await fetch(fixture + '/mode/removal-unavailable', { method: 'POST' });
assert.deepEqual(await (await post('remove-host', { token: setupToken, address: alternateAddress })).json(),
  { state: 'removal_pending' });
assert.deepEqual((await call('maintenance_hosts')).hosts, [{ address }]);
assert.equal((await call('start_host_enrollment', randomUUID(), alternateAddress)).state, 'host_setup_required');
assert.equal((await post('begin-host-pairing', { token: setupToken, address: alternateAddress })).status, 403);
await fetch(fixture + '/mode/normal', { method: 'POST' });
assert.deepEqual(await (await post('remove-host', { token: setupToken, address: alternateAddress })).json(),
  { state: 'removed' });
const newPair = await (await post('begin-host-pairing', { token: setupToken, address: alternateAddress })).json();
assert.notEqual(installedPublicKey(newPair.installCommand), installedPublicKey(alternatePair.installCommand));
const newToken = newPair.installCommand.match(/Authorization: Bearer ([0-9a-f-]{72})/u)[1];
assert.equal((await hostCallback(newToken, hostPin, newPair.id)).status, 200);
assert.equal((await (await post('finish-host-pairing', { token: setupToken, id: newPair.id })).json()).host, alternateAddress);
const staleAssertion = assertion(0x05, origin, staleReview.options.challenge);
assert.equal((await post('approve', { job: staleJob, response: staleAssertion })).status, 200);
for (let retry = 0; retry < 60; retry++) {
  const current = await call('passkey_test_status', staleJob);
  if (current.state !== 'checking_host') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal((await call('passkey_test_status', staleJob)).state, 'target_changed');
assert.equal(await attempts(), beforeExpiry + 1);
console.log('PASS: removing a host blocks access, retries cleanly, and invalidates old approvals after re-enrollment');

await fetch(fixture + '/mode/hang', { method: 'POST' });
const hostJob = randomUUID();
await call('start_host_enrollment', hostJob, address);
const hostReview = await (await post('review-options', { job: hostJob })).json();
const hostApproval = assertion(0x05, origin, hostReview.options.challenge);
assert.equal((await post('approve', { job: hostJob, response: hostApproval })).status, 200);
const count = beforeExpiry + 2;
for (let retry = 0; retry < 60 && await attempts() < count; retry++) {
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal(await attempts(), count);
assert.equal((await call('passkey_test_status', hostJob)).state, 'checking_host');
writeFileSync(receipt, JSON.stringify({ hostJob, hostApproval, count }), { mode: 0o600 });
