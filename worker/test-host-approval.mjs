import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { randomUUID, verify } from 'node:crypto';
import { createHostApprovalKey, signHostApproval } from './src/host-approval.ts';

const { privateKey, publicKey } = createHostApprovalKey();
const approval = {
  job: randomUUID(), enrollment: randomUUID(),
  host: '100.64.0.2', account: 'pasta', command: "printf '%s' 'hello'",
};
const [encoded, signature] = signHostApproval(privateKey, approval, 1_000_000).split('.');
const payload = Buffer.from(encoded, 'base64url');
assert.deepEqual(JSON.parse(payload.toString()), {
  version: 1, ...approval, issued: 1000, expires: 1030,
});
assert.ok(verify(null, payload, publicKey, Buffer.from(signature, 'base64url')));

const scratch = mkdtempSync(join(tmpdir(), 'pasta-approval-'));
try {
  const path = join(scratch, 'public.pem');
  writeFileSync(path, publicKey);
  const script = fileURLToPath(new URL('../experiments/tailnet/host-approval.py', import.meta.url));
  const token = encoded + '.' + signature;
  execFileSync('python3', ['-B', '-c', `
import runpy, sys
script, key, state, token, enrollment, host, account, command = sys.argv[1:]
verify = runpy.run_path(script)["consume"]
def check(**changes):
    target = dict(enrollment=enrollment, host=host, account=account, now=1000)
    target.update(changes)
    return verify(token, key, state, **target)
for changes in (dict(host="100.64.0.3"), dict(enrollment="old"), dict(account="other"), dict(now=1030)):
    try:
        check(**changes)
    except ValueError:
        pass
    else:
        raise AssertionError(changes)
assert check() == command
try:
    check()
except FileExistsError:
    pass
else:
    raise AssertionError("approval replay accepted")
`, script, path, scratch, token, approval.enrollment, approval.host, approval.account, approval.command]);
  console.log('PASS: host verifier accepts a valid approval once and rejects wrong targets and expiry');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
