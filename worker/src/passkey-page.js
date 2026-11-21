const title = document.querySelector('#title');
const details = document.querySelector('#details');
const setup = document.querySelector('#setup');
const tokenInput = document.querySelector('#token');
const action = document.querySelector('#action');
const status = document.querySelector('#status');

async function post(path, body) {
  const response = await fetch('/passkeys/' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error('Request rejected');
  return response.json();
}

function bind(label, run, failure) {
  action.textContent = label;
  action.disabled = false;
  action.onclick = async () => {
    action.disabled = true;
    status.textContent = '';
    try {
      await run();
    } catch {
      status.textContent = failure;
      action.disabled = false;
    }
  };
}

if (location.pathname.endsWith('/onboard')) {
  title.textContent = 'Create your maintenance passkey';
  details.textContent = 'Enter the one-time code, then save the passkey in your device’s password manager.';
  setup.hidden = false;
  bind('Continue', async () => {
    const token = tokenInput.value;
    const optionsJSON = await post('enrollment-options', { token });
    setup.hidden = true;
    tokenInput.value = '';
    bind('Create passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
      await post('enroll', { token, response });
      status.textContent = 'Passkey registered. Return to OpenBot to request an approval test.';
    }, 'Passkey setup did not complete. Retry or reload to enter the setup code again.');
  }, 'The setup code was rejected or a passkey is already registered.');
} else {
  const job = new URLSearchParams(location.search).get('job');
  post('review-options', { job }).then(({ options: optionsJSON, job: request }) => {
    title.textContent = request.dry_run ? 'Approve maintenance test' : 'Verify SSH enrollment';
    details.textContent = request.dry_run
      ? request.operation + ' on ' + request.host + ' as ' + request.execution_identity + '. This dry run will not connect to the host.'
      : 'Ask your host administrator to install the restricted SSH key for ' + request.execution_identity + ' on ' +
        request.host + ' first. This check verifies the pinned host key and runs openbot-enrollment-check-v1 once over SSH.';
    bind('Approve with passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
      await post('approve', { job, response });
      status.textContent = 'Approval verified. You can close this tab and return to OpenBot to check the result.';
    }, 'Approval did not complete. Retry or return to OpenBot if the request expired.');
  }).catch(() => {
    status.textContent = 'This request is unavailable, expired, or already approved.';
  });
}
