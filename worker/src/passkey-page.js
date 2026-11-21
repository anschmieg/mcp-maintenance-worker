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

function hostSetup(token) {
  title.textContent = 'Connect Tailscale';
  details.textContent = 'The Worker will join with the dedicated identity configured by your Tailscale administrator.';
  setup.hidden = true;
  document.querySelector('#resume').hidden = true;
  tokenInput.value = '';
  const guide = document.querySelector('#tailnet-guide');
  const pendingDevice = document.querySelector('#pending-device');
  const policyAddress = document.querySelector('#policy-address');
  const policySnippet = document.querySelector('#tailnet-policy');
  const tag = 'tag:openbot-probe';
  const updatePolicy = () => {
    policySnippet.value = JSON.stringify({
      tagOwners: { [tag]: ['autogroup:admin'] },
      grants: [{ src: [tag], dst: [policyAddress.value.trim() || '<host Tailscale IPv4>'], ip: ['tcp:22'] }],
    }, null, 2);
  };
  policyAddress.oninput = updatePolicy;
  updatePolicy();

  async function connect() {
    pendingDevice.hidden = true;
    const result = await post('prepare-host', { token });
    if (result.state === 'unconfigured') {
      guide.hidden = false;
      details.textContent = 'Set up one restricted Tailscale credential for this tailnet.';
      bind('Connect with OAuth', async () => {
        const clientId = document.querySelector('#oauth-id').value.trim();
        const secret = document.querySelector('#oauth-secret');
        const clientSecret = secret.value.trim();
        secret.value = '';
        await post('configure-tailnet', { token, clientId, clientSecret });
        guide.hidden = true;
        bind('Check Tailnet connection', connect, 'Could not check the connection. Try again.');
        action.disabled = true;
        await connect();
      }, 'Could not use the Tailscale credential. Check that Auth Keys has Write permission for tag:openbot-probe and try again.');
      return;
    }
    if (result.state !== 'connected') {
      details.textContent = 'The Tailnet connection is pending. If your tailnet requires device approval, open Tailscale Machines and approve openbot-tailnet-ssh-probe. Then check the connection again.';
      guide.hidden = true;
      pendingDevice.hidden = false;
      bind('Check Tailnet connection', connect, 'Could not check the connection. Try again.');
      action.disabled = false;
      return;
    }
    title.textContent = 'Add the pilot host';
    details.textContent = 'Create the dedicated account openbot-tailnet-probe on ams. Run this command from that account, then enter its Tailscale IPv4 address and the SHA256 fingerprint printed by the command.';
    const command = document.querySelector('#install-command');
    command.value = result.installCommand;
    command.hidden = false;
    document.querySelector('#address').value = policyAddress.value.trim();
    document.querySelector('#host-settings').hidden = false;
    bind('Save host and review check', async () => {
      const address = document.querySelector('#address').value.trim();
      const fingerprint = document.querySelector('#fingerprint').value.trim();
      const job = await post('save-host', { token, address, fingerprint });
      if (!job.review_url) throw new Error('Review unavailable');
      location.assign(job.review_url);
    }, 'The address or fingerprint could not be saved. Check both values. The pilot host cannot be changed after it is saved.');
  }
  bind('Connect Tailscale', connect, 'Could not connect to Tailscale. Check the setup code and probe configuration, then retry.');
}

if (location.pathname.endsWith('/onboard')) {
  title.textContent = 'Create your maintenance passkey';
  details.textContent = 'Enter the one-time code, then save the passkey in your device’s password manager.';
  setup.hidden = false;
  const resume = document.querySelector('#resume');
  resume.hidden = false;
  resume.onclick = () => hostSetup(tokenInput.value);
  bind('Continue', async () => {
    const token = tokenInput.value;
    const optionsJSON = await post('enrollment-options', { token });
    setup.hidden = true;
    resume.hidden = true;
    tokenInput.value = '';
    bind('Create passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
      await post('enroll', { token, response });
      hostSetup(token);
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
      const approved = await post('approve', { job, response });
      if (request.dry_run) {
        status.textContent = 'Approval verified. You can close this tab and return to OpenBot to check the result.';
        return;
      }
      status.textContent = 'Approval verified. Checking SSH enrollment…';
      let result = approved;
      for (let attempt = 0; result.state === 'checking_host' && attempt < 30; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        result = await post('job-status', { job }).catch(() => result);
      }
      status.textContent = result.state === 'verified' ? 'Host enrollment verified.'
        : 'Host check status: ' + result.state + '. Check job ' + job + ' in OpenBot for the result.';
    }, 'Approval did not complete. Retry or return to OpenBot if the request expired.');
  }).catch(() => {
    status.textContent = 'This request is unavailable, expired, or already approved.';
  });
}
