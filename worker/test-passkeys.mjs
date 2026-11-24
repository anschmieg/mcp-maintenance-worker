import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { createHash, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { encodeCBOR } from '@levischuck/tiny-cbor';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const { PASSKEY_ORIGIN: origin, PASSKEY_SETUP_TOKEN: bootstrapCode, MCP_BEARER_TOKEN: mcpToken } = process.env;
assert.ok(origin && bootstrapCode && mcpToken);
let setupToken = bootstrapCode;
const rpId = new URL(origin).hostname;

async function post(path, body, requestOrigin = origin) {
  if (['review-options', 'approve', 'job-status', 'reconcile'].includes(path) && !Object.hasOwn(body, 'token')) {
    body = { ...body, token: setupToken };
  }
  return fetch(origin + '/passkeys/' + path, {
    method: 'POST', headers: { Origin: requestOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function call(name, job_id, host, command, statement, statementToken) {
  const client = new Client({ name: 'passkey-integration-test', version: '1' });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL('/mcp', origin), {
      requestInit: { headers: { Authorization: 'Bearer ' + (statementToken ?? mcpToken) } },
    }), { timeout: 8000 });
    const result = await client.callTool({ name, arguments: { ...(job_id ? { job_id } : {}), ...(host ? { host } : {}), ...(command === undefined ? {} : { command, statement }) } });
    assert.ok(!result.isError, JSON.stringify(result));
    assert.ok([false, true, null].includes(result.structuredContent.executed));
    return result.structuredContent;
  } finally { await client.close(); }
}

const fixture = 'http://127.0.0.1:8796';
async function installApprovalFixture(script) {
  const publicKey = script.match(/^approval_public_key='([^']+)'$/mu)?.[1];
  const target = script.match(/^approval_target='([^']+)'$/mu)?.[1];
  assert.ok(publicKey && target);
  assert.equal((await fetch(fixture + '/approval-key', {
    method: 'POST', body: JSON.stringify({ ...JSON.parse(target), publicKey }),
  })).status, 200);
}
const attempts = async () => (await (await fetch(fixture + '/attempts')).json()).attempts;
const receipt = process.argv[2];
if (process.argv[3] === 'after-restart') {
  const { hostJob, hostApproval, count, ownerToken } = JSON.parse(readFileSync(receipt, 'utf8'));
  setupToken = ownerToken;
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
assert.equal((await post('setup-state', { token: mcpToken })).status, 403);
assert.deepEqual(await (await post('setup-state', { token: setupToken })).json(), { enrolled: false });
const css = await fetch(origin + '/passkeys/style.css');
assert.match(css.headers.get('Content-Type'), /^text\/css/u);
assert.match(await css.text(), /@media/u);
assert.doesNotMatch(await (await fetch(origin + '/passkeys/onboard')).text(), /Continue host setup/u);
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
const enrolledOwner = await post('enroll', { token: setupToken, response: registration });
assert.equal(enrolledOwner.status, 200);
const { token: firstSession } = await enrolledOwner.json();
assert.deepEqual(await (await post('setup-state', { token: setupToken })).json(), { enrolled: true });
assert.equal((await post('enroll', { token: setupToken, response: registration })).status, 403);
assert.equal((await post('enrollment-options', { token: setupToken })).status, 403);
assert.equal((await post('prepare-host', { token: bootstrapCode })).status, 403);
assert.deepEqual(await (await post('owner-state', {})).json(), { enrolled: true, pairingIdLength: 8, pairingTokenLength: 10 });
const ownerSignIn = await (await post('sign-in-options', {})).json();
const laterSignIn = await (await post('sign-in-options', {})).json();
assert.notEqual(ownerSignIn.id, laterSignIn.id);
const ownerAssertion = assertion(0x05, origin, ownerSignIn.options.challenge);
assert.equal((await post('sign-in', { id: ownerSignIn.id, response: assertion(0x01, origin, ownerSignIn.options.challenge) })).status, 403);
const sessionResponse = await post('sign-in', { id: ownerSignIn.id, response: ownerAssertion });
const ownerCookie = sessionResponse.headers.get('Set-Cookie');
assert.match(ownerCookie, /^__Host-pasta-owner=[0-9a-f-]{72}; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800$/u);
const cookieRequest = (route, body) => fetch(origin + '/passkeys/' + route, {
  method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json', Cookie: ownerCookie.split(';')[0] },
  body: JSON.stringify(body),
});
assert.deepEqual(await (await cookieRequest('review-session', {})).json(), { signedIn: true });
assert.deepEqual(await (await post('review-session', {})).json(), { signedIn: false });
assert.equal((await cookieRequest('job-status', { job })).status, 200);
assert.equal((await cookieRequest('approve', { job })).status, 409);

assert.equal(sessionResponse.status, 200);
setupToken = (await sessionResponse.json()).token;
assert.notEqual(setupToken, firstSession);
assert.equal((await post('prepare-host', { token: firstSession })).status, 403);
assert.equal((await post('sign-in', { id: ownerSignIn.id, response: ownerAssertion })).status, 403);

const webAuthnLibrary = await (await fetch(origin + '/passkeys/webauthn.js')).text();
assert.match(webAuthnLibrary, /startAuthentication/u);
assert.doesNotMatch(webAuthnLibrary, /const title = document/u);
const redirectUri = 'http://127.0.0.1:28417/mcp-auth';
const resource = origin + '/mcp';
const oauthPost = (route, body, headers = {}) => fetch(origin + '/oauth/' + route, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
});
const issuer = await (await fetch(origin + '/.well-known/oauth-authorization-server')).json();
assert.equal(issuer.issuer, origin);
assert.deepEqual(issuer.code_challenge_methods_supported, ['S256']);
assert.equal((await (await fetch(origin + '/.well-known/oauth-protected-resource/mcp')).json()).resource, resource);
const unauthorized = await fetch(resource);
assert.equal(unauthorized.status, 401);
assert.match(unauthorized.headers.get('WWW-Authenticate'), /resource_metadata=/u);
assert.equal((await oauthPost('register', { redirect_uris: ['https://different.example/callback'] })).status, 400);
const clientRegistration = await oauthPost('register', { redirect_uris: [redirectUri], token_endpoint_auth_method: 'none' });
assert.equal(clientRegistration.status, 201);
const { client_id } = await clientRegistration.json();
const verifier = b64(randomBytes(32));
const params = new URLSearchParams({
  client_id, redirect_uri: redirectUri, response_type: 'code', code_challenge_method: 'S256',
  code_challenge: b64(hash(verifier)), state: 'integration-test-state', resource,
});
const authorize = await fetch(issuer.authorization_endpoint + '?' + params);
assert.equal(authorize.status, 200);
const transaction = (await authorize.text()).match(/request: '([A-Za-z0-9_-]{43})'/u)?.[1];
assert.ok(transaction);
const browserHeaders = { Origin: origin };
const foreignChallenge = await (await post('sign-in-options', {})).json();
assert.equal((await oauthPost('approve', {
  request: transaction, id: foreignChallenge.id, response: assertion(0x05, origin, foreignChallenge.options.challenge),
}, browserHeaders)).status, 403);
const challengeResponse = await oauthPost('options', { request: transaction }, browserHeaders);
assert.equal(challengeResponse.status, 200);
const oauthChallenge = await challengeResponse.json();
const approval = { request: transaction, id: oauthChallenge.id, response: assertion(0x05, origin, oauthChallenge.options.challenge) };
assert.equal((await oauthPost('approve', approval, { Origin: 'https://different.example' })).status, 400);
const positiveApproval = await oauthPost('approve', approval, browserHeaders);
assert.equal(positiveApproval.status, 200);
const oauthCookie = positiveApproval.headers.get('Set-Cookie');
assert.match(oauthCookie, /^__Host-pasta-owner=.*; HttpOnly; Secure; SameSite=Strict; Max-Age=604800$/u);
const oauthReview = await fetch(origin + '/passkeys/review-session', {
  method: 'POST', headers: { ...browserHeaders, 'Content-Type': 'application/json', Cookie: oauthCookie.split(';')[0] },
  body: '{}',
});
assert.deepEqual(await oauthReview.json(), { signedIn: true });
assert.equal((await post('prepare-host', { token: oauthCookie.split(';')[0].split('=')[1] })).status, 403);
const callback = new URL((await positiveApproval.json()).redirect);
assert.equal(callback.origin + callback.pathname, redirectUri);
assert.equal(callback.searchParams.get('state'), params.get('state'));
assert.equal(callback.searchParams.get('iss'), origin);
assert.deepEqual(await (await cookieRequest('review-session', {})).json(), { signedIn: true });
const tokenRequest = body => fetch(issuer.token_endpoint, { method: 'POST', body: new URLSearchParams({ client_id, resource, ...body }) });
const codeGrant = { grant_type: 'authorization_code', code: callback.searchParams.get('code'), redirect_uri: redirectUri, code_verifier: verifier };
assert.equal((await tokenRequest({ ...codeGrant, code_verifier: b64(randomBytes(32)) })).status, 400);
assert.equal((await tokenRequest({ ...codeGrant, resource: origin + '/wrong' })).status, 400);
const exchanges = await Promise.all([tokenRequest(codeGrant), tokenRequest(codeGrant)]);
assert.deepEqual(exchanges.map(result => result.status).sort(), [200, 400]);
const { access_token, refresh_token } = await exchanges.find(result => result.ok).json();
const oauthJob = randomUUID();
assert.equal((await call('start_passkey_test', oauthJob, undefined, undefined, undefined, access_token)).executed, false);
assert.equal((await cookieRequest('approve', { job: oauthJob, token: access_token })).status, 403);
const refresh = { grant_type: 'refresh_token', refresh_token };
const renewed = await tokenRequest(refresh);
assert.equal(renewed.status, 200);
assert.equal((await tokenRequest(refresh)).status, 400);
assert.equal((await fetch(resource, { headers: { Authorization: 'Bearer ' + access_token } })).status, 401);
assert.equal((await call('passkey_test_status', oauthJob, undefined, undefined, undefined, (await renewed.json()).access_token)).executed, false);
console.log('PASS: OAuth discovery, owner passkey, PKCE, single-use exchange, refresh, and MCP authorization');

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
const canceledPair = await (await post('begin-host-pairing', { token: setupToken, address })).json();
assert.equal((await post('cancel-pairing', { token: mcpToken, id: canceledPair.id })).status, 403);
assert.deepEqual(await (await post('cancel-pairing', { token: setupToken, id: canceledPair.id })).json(), { state: 'invalidated' });
assert.equal((await downloadPairingScript(canceledPair)).status, 403);
const terminalCancelPair = await (await post('begin-host-pairing', { token: setupToken, address })).json();
assert.equal((await fetch(origin + '/passkeys/host-pairing?pair=' + terminalCancelPair.id, {
  method: 'POST', headers: { Authorization: 'Bearer ' + terminalCancelPair.download.token },
  body: new URLSearchParams({ account_action: 'canceled' }),
})).status, 200);
assert.equal((await downloadPairingScript(terminalCancelPair)).status, 403);
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: terminalCancelPair.id })).json(), {
  state: 'pairing_canceled',
});
const pair = await (await post('begin-host-pairing', { token: setupToken, address })).json();
assert.equal(pair.account, 'pasta-mcp');
assert.match(pair.id, /^[A-Za-z0-9]{8}$/u);
assert.match(pair.download.token, /^[A-Za-z0-9]{10}$/u);
assert.equal(pair.installCommand, [
  "curl -fsS '" + pair.download.url + "' -H 'Authorization: Bearer " +
    pair.download.token + "' -o pasta-setup.sh &&",
  'sh pasta-setup.sh',
].join('\n'));
execFileSync('/bin/sh', ['-n', '-c', pair.installCommand]);
async function downloadPairingScript(pair, token = pair.download.token) {
  return fetch(pair.download.url, { headers: { Authorization: 'Bearer ' + token } });
}
assert.equal((await fetch(pair.download.url)).status, 403);
assert.equal((await downloadPairingScript(pair, mcpToken)).status, 403);
const install = await (await downloadPairingScript(pair)).text();
await installApprovalFixture(install);
assert.match(install, /ssh-keygen.*ssh_host_ed25519_key.pub/u);
assert.match(install, /account='pasta-mcp'/u);
assert.match(install, /useradd --system --create-home/u);
assert.match(install, /read -r answer;/u);
assert.match(install, /Show what setup installs/u);
assert.match(install, /Choice \[1\]/u);
assert.ok(install.includes('runuser -u "$account"'));
assert.match(install, /tailscale ip -4/u);
execFileSync('/bin/sh', ['-n', '-c', install]);
const callbackToken = pair.download.token;
function hostCallback(token, fingerprint, pairing = pair.id, action = 'created', account) {
  return fetch(origin + '/passkeys/host-pairing?pair=' + pairing, {
    method: 'POST', headers: { Authorization: 'Bearer ' + token },
    body: new URLSearchParams({ fingerprint, account_action: action, ...(account === undefined ? {} : { account }) }),
  });
}
assert.equal((await hostCallback(mcpToken, hostPin)).status, 403);
assert.equal((await hostCallback(callbackToken, 'invalid')).status, 403);
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: pair.id })).json(),
  { state: 'waiting_for_host' });
assert.equal((await hostCallback(callbackToken, hostPin, pair.id, 'invalid')).status, 403);
assert.equal((await hostCallback(callbackToken, hostPin)).status, 200);
assert.equal((await hostCallback(callbackToken, hostPin)).status, 403);
assert.equal((await downloadPairingScript(pair)).status, 403);
assert.equal((await post('finish-host-pairing', { token: mcpToken, id: pair.id })).status, 403);
const hostSetup = await (await post('finish-host-pairing', { token: setupToken, id: pair.id })).json();
assert.equal(hostSetup.state, 'pending');
assert.equal(hostSetup.host, address);
assert.equal(hostSetup.execution_identity, 'pasta-mcp');
assert.equal(hostSetup.account_action, 'created');
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
const alternateInstall = await (await downloadPairingScript(alternatePair)).text();
await installApprovalFixture(alternateInstall);
assert.notEqual(installedPublicKey(alternateInstall), installedPublicKey(install));
const alternateToken = alternatePair.download.token;
assert.equal((await hostCallback(alternateToken, hostPin, pair.id)).status, 403);
assert.equal((await hostCallback(alternateToken, hostPin, alternatePair.id, 'reused')).status, 200);
const alternateSetup = await (await post('finish-host-pairing', { token: setupToken, id: alternatePair.id })).json();
assert.equal(alternateSetup.host, alternateAddress);
assert.equal(alternateSetup.account_action, 'reused');
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
const newInstall = await (await downloadPairingScript(newPair)).text();
await installApprovalFixture(newInstall);
assert.notEqual(installedPublicKey(newInstall), installedPublicKey(alternateInstall));
const newToken = newPair.download.token;
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

const restartJob = randomUUID();
const restartRequest = await call('request_service_restart', restartJob, address);
assert.equal(restartRequest.state, 'pending');
assert.equal(restartRequest.service, 'openbot-maintenance-demo.service');
assert.equal(restartRequest.host, address);
assert.equal((await call('request_service_restart', restartJob, alternateAddress)).state, 'job_id_in_use');
assert.equal((await call('start_host_enrollment', restartJob, address)).state, 'job_id_in_use');
const { options: restartOptions } = await (await post('review-options', { job: restartJob })).json();
assert.equal((await post('approve', { job: restartJob, response })).status, 409);
const restartApproval = assertion(0x05, origin, restartOptions.challenge);
assert.equal(await attempts(), beforeExpiry + 1);
const approvalRace = await Promise.all([
  post('approve', { job: restartJob, response: restartApproval }),
  post('approve', { job: restartJob, response: restartApproval }),
]);
assert.deepEqual(approvalRace.map(result => result.status).sort(), [200, 409]);
for (let retry = 0; retry < 60; retry++) {
  const current = await call('passkey_test_status', restartJob);
  if (current.state !== 'checking_host') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal((await call('passkey_test_status', restartJob)).state, 'service_restarted');
assert.equal((await call('request_service_restart', restartJob, address)).state, 'service_restarted');
assert.equal((await (await fetch(fixture + '/attempts')).json()).restarts, 1);
console.log('PASS: exact service restart uses one owner passkey, is target-bound, and executes once');

await fetch(fixture + '/mode/automatic-discovery', { method: 'POST' });
const macPair = await (await post('begin-host-pairing', { token: setupToken })).json();
const reportUnsupported = token => fetch(origin + '/passkeys/claim-host?pair=' + macPair.id, {
  method: 'POST', headers: { Authorization: 'Bearer ' + token },
  body: new URLSearchParams({ error: 'unsupported_platform' }),
});
assert.equal((await reportUnsupported(mcpToken)).status, 403);
assert.equal((await reportUnsupported(macPair.download.token)).status, 204);
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: macPair.id })).json(),
  { state: 'unsupported_platform' });
assert.equal((await downloadPairingScript(macPair)).status, 403);
assert.equal((await reportUnsupported(macPair.download.token)).status, 403);
const detectedPair = await (await post('begin-host-pairing', { token: setupToken })).json();
assert.match(detectedPair.id, /^[A-Za-z0-9]{8}$/u);
assert.match(detectedPair.download.token, /^[A-Za-z0-9]{10}$/u);
const previewResponse = await fetch(origin + '/passkeys/setup-preview');
assert.equal(previewResponse.status, 200);
const preview = await previewResponse.text();
assert.match(preview, /detect_host\(\)/u);
assert.ok(!preview.includes(detectedPair.download.token));
assert.ok(!preview.includes(detectedPair.id));
assert.doesNotMatch(preview, /^(?:pairing_token|claim_url)=/mu);
const detection = await (await downloadPairingScript(detectedPair)).text();
assert.match(detection, /tailscale ip -4/u);
assert.doesNotMatch(detection, /ssh-ed25519/u);
execFileSync('/bin/sh', ['-n', '-c', detection]);
const claimHost = async (address, pairing = detectedPair) => fetch(origin + '/passkeys/claim-host?pair=' + pairing.id, {
  method: 'POST', headers: { Authorization: 'Bearer ' + pairing.download.token },
  body: new URLSearchParams({ address }),
});
assert.equal((await hostCallback(detectedPair.download.token, hostPin, detectedPair.id)).status, 403);
assert.equal((await claimHost('100.127.0.20')).status, 403);
const detectedAddress = '100.64.0.4';
const claim = await claimHost(detectedAddress);
assert.equal(claim.status, 200);
const detectedInstaller = await claim.text();
await installApprovalFixture(detectedInstaller);
assert.match(detectedInstaller, /target_address='100\.64\.0\.4'/u);
assert.match(detectedInstaller, /target_name='Auto host'/u);
assert.match(detectedInstaller, /Use an existing login account/u);
assert.match(detectedInstaller, /sshd -T -C/u);
execFileSync('/bin/sh', ['-n', '-c', detectedInstaller]);
const fileInstaller = detectedInstaller.match(/^install_generated_file\(\) \{[\s\S]+?^\}/mu)[0];
const installDestination = receipt + '.installed';
const installTest = 'as_admin() { "$@"; }\n' + fileInstaller + '\ninstall_generated_file "$1" 0600';
execFileSync('/bin/sh', ['-c', installTest, 'test', installDestination], { input: 'approval configuration\n' });
assert.equal(readFileSync(installDestination, 'utf8'), 'approval configuration\n');
assert.equal(statSync(installDestination).mode & 0o777, 0o600);
assert.throws(() => execFileSync('/bin/sh', ['-c', installTest, 'test', installDestination], { input: '' }));
assert.equal(readFileSync(installDestination, 'utf8'), 'approval configuration\n');
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: detectedPair.id })).json(),
  { state: 'waiting_for_confirmation', host: 'Auto host' });
await fetch(fixture + '/mode/wrong-pin', { method: 'POST' });
const detectedToken = detectedPair.download.token;
const existingAccount = 'ops-admin';
for (const account of [undefined, 'root', '../operator', 'ops-admin\n', 'ops;admin']) {
  assert.equal((await hostCallback(detectedToken, hostPin, detectedPair.id, 'existing', account)).status, 403);
}
assert.equal((await hostCallback(detectedToken, hostPin, detectedPair.id, 'reused', existingAccount)).status, 403);
assert.equal((await hostCallback(detectedToken, hostPin, detectedPair.id, 'existing', existingAccount)).status, 200);
assert.equal((await hostCallback(detectedToken, hostPin, detectedPair.id, 'existing', 'different-admin')).status, 403);
async function finishDetectedPair(retry = false) {
  let status = await (await post('finish-host-pairing', { token: setupToken, id: detectedPair.id, retry })).json();
  for (let attempt = 0; status.state === 'verifying' && attempt < 60; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 100));
    status = await (await post('finish-host-pairing', { token: setupToken, id: detectedPair.id })).json();
  }
  return status;
}
assert.deepEqual(await finishDetectedPair(), { state: 'verification_failed', failure: 'host_key_unverified' });
assert.ok(!(await call('maintenance_hosts')).hosts.some(host => host.address === detectedAddress));
await fetch(fixture + '/mode/normal', { method: 'POST' });
const verified = await finishDetectedPair(true);
assert.deepEqual(verified, { state: 'verified', host: 'Auto host' });
const receiptUrl = origin + '/passkeys/pair-result?pair=' + detectedPair.id;
assert.equal((await fetch(receiptUrl)).status, 403);
assert.equal(await (await fetch(receiptUrl, {
  headers: { Authorization: 'Bearer ' + detectedPair.download.token },
})).text(), 'verified\n');
assert.deepEqual(await (await post('finish-host-pairing', { token: setupToken, id: detectedPair.id })).json(), verified);
assert.ok((await call('maintenance_hosts')).hosts.some(host => host.address === detectedAddress));
const secondAuto = await (await post('begin-host-pairing', { token: setupToken })).json();
assert.notEqual(secondAuto.id, detectedPair.id);
assert.equal((await claimHost(detectedAddress, secondAuto)).status, 409);
assert.deepEqual(await (await post('cancel-pairing', { token: setupToken, id: detectedPair.id })).json(),
  { state: 'already_paired' });
const recoveryAddress = '100.64.0.5';
assert.equal((await claimHost(recoveryAddress, secondAuto)).status, 200);
await fetch(fixture + '/mode/wrong-pin', { method: 'POST' });
assert.equal((await hostCallback(secondAuto.download.token, hostPin, secondAuto.id, 'created', 'pasta-mcp')).status, 200);
let failed;
for (let attempt = 0; attempt < 60; attempt++) {
  failed = await (await post('finish-host-pairing', { token: setupToken, id: secondAuto.id })).json();
  if (failed.state !== 'verifying') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.deepEqual(failed, { state: 'verification_failed', failure: 'host_key_unverified' });
assert.deepEqual(await (await post('cancel-pairing', { token: setupToken, id: secondAuto.id })).json(),
  { state: 'invalidated' });
assert.equal((await downloadPairingScript(secondAuto)).status, 403);
await fetch(fixture + '/mode/normal', { method: 'POST' });
const replacement = await (await post('begin-host-pairing', { token: setupToken })).json();
assert.equal((await claimHost(recoveryAddress, replacement)).status, 200);
console.log('PASS: passkey resume, host detection, rejection of invisible devices, verification retry, and repeat pairing');

const existingRestart = randomUUID();
const initialRestarts = (await (await fetch(fixture + '/attempts')).json()).restarts;
const existingRequest = await call('request_service_restart', existingRestart, detectedAddress);
assert.equal(existingRequest.state, 'pending');
assert.equal(existingRequest.execution_identity, existingAccount);
assert.equal((await (await fetch(fixture + '/attempts')).json()).restarts, initialRestarts);
assert.equal((await post('approve', { job: existingRestart, response: restartApproval })).status, 409);
const existingReview = await (await post('review-options', { job: existingRestart })).json();
const existingApproval = assertion(0x05, origin, existingReview.options.challenge);
assert.equal((await post('approve', { job: existingRestart, response: existingApproval })).status, 200);
assert.equal((await post('approve', { job: existingRestart, response: existingApproval })).status, 409);
for (let retry = 0; retry < 60; retry++) {
  if ((await call('passkey_test_status', existingRestart)).state !== 'checking_host') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal((await call('passkey_test_status', existingRestart)).state, 'service_restarted');
assert.equal((await (await fetch(fixture + '/attempts')).json()).restarts, initialRestarts + 1);
console.log('PASS: selected existing account is bound to SSH and a fresh one-time restart approval');

const commandJob = randomUUID();
const expectedOutput = 'pasta-dynamic-' + randomUUID();
const command = "printf '%s' '" + expectedOutput + "'";
const statement = 'Print a test message to prove that the flow works.';
const namedRequest = await call('request_maintenance_command', randomUUID(), detectedAddress, command, statement);
assert.equal(namedRequest.host_name, 'Auto host');
assert.equal(namedRequest.host, detectedAddress);
const beforeCommand = await attempts();
const invalid = await call('request_maintenance_command', commandJob, address, command + ' |', statement);
assert.equal(invalid.state, 'invalid_command');
const commandRequest = await call('request_maintenance_command', commandJob, address, command, statement);
assert.equal(commandRequest.state, 'pending');
assert.equal(commandRequest.executed, false);
assert.equal(await attempts(), beforeCommand);
assert.equal((await call('start_host_enrollment', commandJob, address)).state, 'job_id_in_use');
assert.equal((await call('request_maintenance_command', commandJob, address,
  '/usr/bin/sudo -n -- /usr/bin/systemctl restart openbot-maintenance-demo.service', statement)).state, 'job_id_in_use');
const commandReview = await (await post('review-options', { job: commandJob })).json();
assert.equal(commandReview.job.command, command);
assert.equal(commandReview.job.statement, statement);
assert.equal(commandReview.job.explanation, 'Scope assessment unavailable. Review the command directly.');
assert.equal((await call('request_maintenance_command', commandJob, address, command,
  'A different reason.')).state, 'job_id_in_use');
assert.equal(commandReview.job.host, address);
const commandApproval = assertion(0x05, origin, commandReview.options.challenge);
assert.equal((await post('approve', { job: commandJob, response: commandApproval })).status, 200);
assert.equal((await post('approve', { job: commandJob, response: commandApproval })).status, 409);
let commandResult = await call('passkey_test_status', commandJob);
for (let retry = 0; commandResult.state === 'checking_host' && retry < 60; retry++) {
  await new Promise(resolve => setTimeout(resolve, 100));
  commandResult = await call('passkey_test_status', commandJob);
}
assert.equal(commandResult.executed, true);
assert.equal(commandResult.command, command);
assert.equal(commandResult.state, 'command_completed');
assert.equal(commandResult.stdout, expectedOutput);
assert.equal(commandResult.exit_status, 0);
for (const path of ['review-options', 'job-status', 'approve']) {
  assert.equal((await post(path, { job: commandJob, token: null })).status, 403);
}
const publicResult = await (await post('job-status', { job: commandJob })).json();
assert.equal(publicResult.state, 'command_completed');
assert.equal(publicResult.stdout, undefined);
assert.equal(publicResult.stderr, undefined);
assert.equal(await attempts(), beforeCommand + 1);
console.log('PASS: exact command shown in review, command substitution rejected, SSH executed once after approval');

await fetch(fixture + '/mode/interrupted', { method: 'POST' });
const uncertainJob = randomUUID();
const retryJob = randomUUID();
for (const id of [uncertainJob, retryJob]) {
  assert.equal((await call('request_maintenance_command', id, address, command, statement)).state, 'pending');
}
async function approveJob(job) {
  const { options } = await (await post('review-options', { job })).json();
  return post('approve', { job, response: assertion(0x05, origin, options.challenge) });
}
assert.equal((await approveJob(uncertainJob)).status, 200);
let uncertain;
for (let attempt = 0; attempt < 100; attempt++) {
  uncertain = await call('passkey_test_status', uncertainJob);
  if (uncertain.state !== 'checking_host') break;
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal(uncertain.state, 'check_outcome_unknown');
assert.equal((await approveJob(retryJob)).status, 409);
assert.equal((await post('reconcile', { job: uncertainJob, token: null })).status, 403);
assert.equal((await post('reconcile', { job: uncertainJob })).status, 200);
await fetch(fixture + '/mode/normal', { method: 'POST' });
assert.equal((await approveJob(retryJob)).status, 200);
for (let attempt = 0; attempt < 60 && (await call('passkey_test_status', retryJob)).state === 'checking_host'; attempt++) {
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal((await call('passkey_test_status', retryJob)).state, 'command_completed');
console.log('PASS: unknown command outcome requires owner reconciliation before a fresh approval');

const count = await attempts() + 1;
await fetch(fixture + '/mode/hang', { method: 'POST' });
const hostJob = randomUUID();
await call('start_host_enrollment', hostJob, address);
const hostReview = await (await post('review-options', { job: hostJob })).json();
const hostApproval = assertion(0x05, origin, hostReview.options.challenge);
assert.equal((await post('approve', { job: hostJob, response: hostApproval })).status, 200);
for (let retry = 0; retry < 60 && await attempts() < count; retry++) {
  await new Promise(resolve => setTimeout(resolve, 100));
}
assert.equal(await attempts(), count);
assert.equal((await call('passkey_test_status', hostJob)).state, 'checking_host');
writeFileSync(receipt, JSON.stringify({ ownerToken: setupToken, hostJob, hostApproval, count }), { mode: 0o600 });
