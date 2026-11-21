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
  details.textContent = 'Sign in to add the Worker as a device on your tailnet. It inherits the network access your Tailscale policy gives devices signed in as you. SSH pairing is required separately.';
  setup.hidden = true;
  document.querySelector('#resume').hidden = true;
  tokenInput.value = '';
  const guide = document.querySelector('#tailnet-guide');
  const pendingDevice = document.querySelector('#pending-device');
  const policySnippet = document.querySelector('#tailnet-policy');
  const taggedSetup = document.querySelector('#tagged-setup');
  const login = document.querySelector('#device-login');
  const tag = 'tag:openbot-probe';
  policySnippet.value = JSON.stringify({ tagOwners: { [tag]: ['autogroup:admin'] } }, null, 2);

  async function connect() {
    let result = await post('prepare-host', { token });
    if (result.state === 'probe_unavailable') throw new Error('Probe unavailable');
    if (result.state === 'unconfigured') {
      taggedSetup.hidden = false;
      taggedSetup.onclick = () => {
        taggedSetup.hidden = true;
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
      };
      bind('Sign in to Tailscale', async () => {
        await post('start-device-login', { token });
        await connect();
      }, 'Could not start Tailscale sign-in. Try again.');
      return;
    }
    taggedSetup.hidden = true;
    guide.hidden = true;
    for (let attempt = 0; result.state === 'tailnet_pending' && attempt < 60; attempt++) {
      details.textContent = result.needsDeviceApproval
        ? 'Your tailnet requires device approval. Approve openbot-tailnet-ssh-probe in Tailscale Machines.'
        : result.loginUrl ? 'Open Tailscale to complete sign-in. This page will continue when the device joins.'
          : result.deviceTag ? 'Waiting for the tagged device. If device approval is required, approve it in Tailscale Machines.'
            : 'Waiting for Tailscale to connect…';
      login.hidden = !result.loginUrl;
      if (result.loginUrl) login.href = result.loginUrl;
      pendingDevice.hidden = !result.needsDeviceApproval && !result.deviceTag;
      await new Promise(resolve => setTimeout(resolve, 5000));
      result = await post('prepare-host', { token });
    }
    if (result.state !== 'connected') {
      bind('Check Tailscale connection', connect, 'Could not check the connection. Try again.');
      return;
    }
    login.hidden = true;
    pendingDevice.hidden = true;
    title.textContent = 'Add a pilot host';
    details.textContent = 'Choose the host you want to enroll.';
    const command = document.querySelector('#install-command');
    const address = document.querySelector('#address');
    const picker = document.querySelector('#device');
    for (const device of result.devices ?? []) {
      const option = document.createElement('option');
      option.value = device.address;
      option.textContent = device.name;
      picker.append(option);
    }
    document.querySelector('#device-picker').hidden = !result.devices?.length;
    const targetAddress = () => picker.value || address.value.trim();
    let updateGrant = () => {};
    if (result.deviceTag) {
      const grant = document.querySelector('#grant-policy');
      updateGrant = () => {
        grant.value = JSON.stringify({
          grants: [{ src: [result.deviceTag], dst: [targetAddress() || '<host Tailscale IPv4>'], ip: ['tcp:22'] }],
        }, null, 2);
      };
      address.oninput = updateGrant;
      updateGrant();
      document.querySelector('#host-grant').hidden = false;
    }
    picker.onchange = () => {
      document.querySelector('#manual-address').hidden = Boolean(picker.value);
      updateGrant();
    };
    document.querySelector('#host-settings').hidden = false;
    bind('Get host setup command', async () => {
      const pair = await post('begin-host-pairing', { token, address: targetAddress() });
      if (pair.installCommand) {
        command.value = pair.installCommand;
        command.hidden = false;
        const copy = document.querySelector('#copy-install');
        copy.hidden = false;
        copy.onclick = async () => {
          try {
            await navigator.clipboard.writeText(command.value);
            copy.textContent = 'Copied';
          } catch {
            command.select();
          }
        };
        details.textContent = 'Run this command on the selected host as the dedicated SSH account openbot-tailnet-probe. It installs the public key and sends the host fingerprint back here.';
      }
      document.querySelector('#host-settings').hidden = true;
      status.textContent = 'Waiting for the host…';
      for (let attempt = 0; attempt < 180; attempt++) {
        const job = await post('finish-host-pairing', { token, id: pair.id });
        if (job.review_url) {
          location.assign(job.review_url);
          return;
        }
        if (job.state !== 'waiting_for_host') {
          status.textContent = 'Host check status: ' + job.state + '.';
          return;
        }
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
      throw new Error('Pairing expired');
    }, 'Host setup did not complete. Reload the page to retry.');
  }
  const failure = 'Could not connect to Tailscale. Check the setup code and probe configuration, then retry.';
  action.textContent = 'Checking Tailscale connection…';
  action.disabled = true;
  void connect().catch(() => {
    status.textContent = failure;
    bind('Check Tailscale connection', connect, failure);
  });
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
