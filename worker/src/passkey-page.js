const title = document.querySelector('#title');
const details = document.querySelector('#details');
const setup = document.querySelector('#setup');
const tokenInput = document.querySelector('#token');
const action = document.querySelector('#action');
const status = document.querySelector('#status');
const steps = document.querySelector('#steps');

function showStep(name) {
  steps.hidden = false;
  for (const step of steps.querySelectorAll('[data-step]')) {
    if (step.dataset.step === name) step.setAttribute('aria-current', 'step');
    else step.removeAttribute('aria-current');
  }
}

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
  showStep('tailnet');
  title.textContent = 'Connect Tailscale';
  details.textContent = 'Sign in to add the Worker as a device on your tailnet. It inherits the network access your Tailscale policy gives devices signed in as you. SSH pairing is required separately.';
  setup.hidden = true;
  tokenInput.value = '';
  const guide = document.querySelector('#tailnet-guide');
  const pendingDevice = document.querySelector('#pending-device');
  const policySnippet = document.querySelector('#tailnet-policy');
  const taggedSetup = document.querySelector('#tagged-setup');
  const login = document.querySelector('#device-login');
  const tag = 'tag:openbot-probe';
  policySnippet.value = JSON.stringify({ tagOwners: { [tag]: ['autogroup:admin'] } }, null, 2);

  function showManagedHosts({ managedHosts, devices }) {
    const section = document.querySelector('#manage-hosts');
    const select = document.querySelector('#remove-host-address');
    const button = document.querySelector('#remove-host');
    const message = document.querySelector('#remove-host-status');
    select.replaceChildren();
    section.hidden = !managedHosts?.length;
    for (const host of managedHosts ?? []) {
      const name = devices?.find(device => device.address === host.address)?.name;
      const label = name ? name + ' (' + host.address + ')' : host.address;
      select.add(new Option(label + (host.removalPending ? ' — removal pending' : ''), host.address));
    }
    button.onclick = async () => {
      const address = select.value;
      if (!address || !confirm('Remove ' + address + ' from this Worker? A job already running may finish.')) return;
      button.disabled = true;
      select.disabled = true;
      try {
        const result = await post('remove-host', { token, address });
        if (result.state === 'removal_pending') {
          message.textContent = 'New checks are blocked. Select Remove host again to finish removing the SSH key from the Worker.';
          return;
        }
        select.querySelector('option:checked')?.remove();
        message.textContent = 'Host removed. Remove the old public key from the host’s authorized_keys file as well.';
      } catch {
        message.textContent = 'Could not remove the host. Try again.';
      } finally {
        button.disabled = select.options.length === 0;
        select.disabled = button.disabled;
      }
    };
  }

  async function connect() {
    let result = await post('prepare-host', { token });
    showManagedHosts(result);
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
        ? 'Your tailnet requires device approval. Approve the PaSTA device in Tailscale Machines.'
        : result.loginUrl ? 'Open Tailscale to complete sign-in. This page will continue when the device joins.'
          : result.deviceTag ? 'Waiting for the tagged device. If device approval is required, approve it in Tailscale Machines.'
            : 'Waiting for Tailscale to connect…';
      login.hidden = !result.loginUrl;
      action.hidden = Boolean(result.loginUrl) || Boolean(result.needsDeviceApproval);
      if (result.loginUrl) login.href = result.loginUrl;
      pendingDevice.hidden = !result.needsDeviceApproval && !result.deviceTag;
      await new Promise(resolve => setTimeout(resolve, 5000));
      result = await post('prepare-host', { token });
    }
    action.hidden = false;
    if (result.state !== 'connected') {
      bind('Check Tailscale connection', connect, 'Could not check the connection. Try again.');
      return;
    }
    login.hidden = true;
    pendingDevice.hidden = true;
    showStep('host');
    title.textContent = 'Add a host';
    details.textContent = 'Choose the host you want to enroll.';
    const command = document.querySelector('#install-command');
    const address = document.querySelector('#address');
    const picker = document.querySelector('#device');
    picker.length = 1;
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
        const commandPanel = document.querySelector('#pair-command');
        commandPanel.hidden = false;
        const copy = document.querySelector('#copy-install');
        const script = document.querySelector('#script-preview');
        script.value = '';
        script.parentElement.ontoggle = async () => {
          if (!script.parentElement.open || script.value) return;
          if (!pair.download) return;
          try {
            const response = await fetch(pair.download.url, { headers: { Authorization: 'Bearer ' + pair.download.token } });
            if (!response.ok) throw new Error();
            script.value = await response.text();
          } catch {
            script.value = 'Could not load the script. Generate a fresh command and try again.';
          }
        };
        copy.onclick = async () => {
          try {
            await navigator.clipboard.writeText(command.value);
            copy.textContent = 'Copied';
          } catch {
            command.select();
          }
        };
        title.textContent = 'Pair the selected host';
        details.textContent = 'The installer asks whether to create or use the ' + pair.account + ' account. It then sends the host fingerprint back here.';
      }
      document.querySelector('#host-settings').hidden = true;
      action.hidden = true;
      status.textContent = 'Waiting for the command to finish on the selected host. If it fails, check the message in that terminal.';
      let pairingCanceled = false;
      for (let attempt = 0; attempt < 180; attempt++) {
        const job = await post('finish-host-pairing', { token, id: pair.id });
        if (job.review_url) {
          location.assign(job.review_url);
          return;
        }
        if (job.state === 'pairing_canceled') { pairingCanceled = true; break; }
        if (job.state === 'pairing_expired') break;
        if (job.state !== 'waiting_for_host') {
          status.textContent = 'Host check status: ' + job.state + '.';
          return;
        }
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
      document.querySelector('#pair-command').hidden = true;
      status.textContent = pairingCanceled ? 'Host pairing was canceled in the terminal.'
        : 'This command has expired or was replaced. Generate a fresh one to continue.';
      action.hidden = false;
      bind('Generate a new command', connect, 'Could not refresh the host list. Try again.');
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
  showStep('access');
  title.textContent = 'Set up maintenance access';
  details.textContent = 'Enter your setup code to get started or pick up where you left off.';
  setup.hidden = false;
  setup.onsubmit = event => {
    event.preventDefault();
    action.click();
  };
  tokenInput.addEventListener('keydown', event => {
    if (event.key === 'Enter') { event.preventDefault(); action.click(); }
  });
  bind('Continue', async () => {
    const token = tokenInput.value.trim();
    if (!token) {
      tokenInput.reportValidity();
      action.disabled = false;
      return;
    }
    const { enrolled } = await post('setup-state', { token });
    if (enrolled) {
      hostSetup(token);
      return;
    }
    const optionsJSON = await post('enrollment-options', { token });
    setup.hidden = true;
    tokenInput.value = '';
    title.textContent = 'Create your passkey';
    details.textContent = 'Use your device’s passkey prompt. You’ll use this passkey to approve maintenance jobs.';
    bind('Create passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
      await post('enroll', { token, response });
      hostSetup(token);
    }, 'Passkey setup did not complete. You can retry or refresh for a new request.');
  }, 'That setup code did not work. Check the code and try again.');
} else {
  const job = new URLSearchParams(location.search).get('job');
  post('review-options', { job }).then(({ options: optionsJSON, job: request }) => {
    title.textContent = request.service ? 'Approve service restart'
      : request.dry_run ? 'Approve maintenance test' : 'Verify SSH enrollment';
    details.textContent = request.service
      ? 'Restart ' + request.service + ' once on ' + request.host + ' as ' + request.run_as +
        '. The service may be briefly unavailable.'
      : request.dry_run
      ? request.operation + ' on ' + request.host + ' as ' + request.execution_identity + '. This dry run will not connect to the host.'
      : 'Ask your host administrator to install the restricted SSH key for ' + request.execution_identity + ' on ' +
        request.host + ' first. This check verifies the pinned host key and runs openbot-enrollment-check-v1 once over SSH.';
    bind(request.service ? 'Approve restart with passkey' : 'Approve with passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
      const approved = await post('approve', { job, response });
      if (request.dry_run) {
        status.textContent = 'Approval verified. You can close this tab and return to your MCP client to check the result.';
        return;
      }
      status.textContent = request.service ? 'Approval verified. Restarting the service…' : 'Approval verified. Checking SSH enrollment…';
      let result = approved;
      for (let attempt = 0; result.state === 'checking_host' && attempt < 30; attempt++) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        result = await post('job-status', { job }).catch(() => result);
      }
      status.textContent = result.state === 'service_restarted' ? 'Service restarted.'
        : result.state === 'verified' ? 'Host enrollment verified.'
        : 'Host check status: ' + result.state + '. Check job ' + job + ' in your MCP client for the result.';
    }, 'Approval did not complete. Retry or return to your MCP client if the request expired.');
  }).catch(() => {
    status.textContent = 'This request is unavailable, expired, or already approved.';
  });
}
