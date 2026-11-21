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
    details.textContent = 'Run the setup command on the Linux machine you want to add. PaSTA detects it over Tailscale. Choose the SSH account in the terminal.';
    const command = document.querySelector('#install-command');
    const panel = document.querySelector('#pair-command');
    const copy = document.querySelector('#copy-install');
    const script = document.querySelector('#script-preview');
    const activePair = sessionStorage.getItem('pasta-pair');
    const failure = 'Could not check the pairing. Try again.';

    async function waitForPair(pairId, retry = false) {
      for (let attempt = 0; attempt < 360; attempt++) {
        if (sessionStorage.getItem('pasta-pair') !== pairId) return;
        const progress = await post('finish-host-pairing', { token, id: pairId, retry });
        retry = false;
        if (sessionStorage.getItem('pasta-pair') !== pairId) return;
        if (progress.state === 'verified') {
          sessionStorage.removeItem('pasta-pair');
          panel.hidden = true;
          title.textContent = 'Host paired and verified';
          details.textContent = progress.host + ' is ready for maintenance.';
          status.textContent = '';
          bind('Add another host', newPair, failure);
          return;
        }
        if (progress.state === 'verification_failed') {
          panel.hidden = true;
          const messages = {
            host_key_unverified: 'The SSH host key did not match. Check that OpenSSH is serving the key on this host.',
            ssh_authentication_failed: 'The host rejected the SSH key. Check SSH access for the account in the terminal.',
            diagnostic_failed: 'The SSH check returned an unexpected result. Check the account’s restricted key.',
            target_changed: 'This address already has a different enrollment. Check the enrolled host before retrying.',
          };
          status.textContent = messages[progress.failure] ?? 'PaSTA could not complete the SSH check. Check network access to port 22, then retry.';
          bind('Retry SSH verification', () => waitForPair(pairId, true), failure);
          return;
        }
        if (progress.state === 'pairing_canceled' || progress.state === 'pairing_expired') {
          sessionStorage.removeItem('pasta-pair');
          panel.hidden = true;
          status.textContent = progress.state === 'pairing_canceled' ? 'Host pairing was canceled in the terminal.'
            : 'This command expired. Generate a fresh one to continue.';
          bind('Get a new setup command', newPair, failure);
          return;
        }
        status.textContent = progress.state === 'verifying' ? 'Verifying SSH on ' + (progress.host ?? 'the host') + '…'
          : progress.state === 'waiting_for_confirmation' ? 'Detected ' + (progress.host ?? 'the host') + '. Confirm pairing in the terminal.'
          : 'Waiting for you to run the setup command on a host.';
        await new Promise(resolve => setTimeout(resolve, 2500));
      }
      bind('Check pairing status', () => waitForPair(pairId), failure);
    }

    async function newPair() {
      const pair = await post('begin-host-pairing', { token });
      sessionStorage.setItem('pasta-pair', pair.id);
      title.textContent = 'Add a host';
      details.textContent = 'Run this command on the Linux host you want to add. Confirm the detected device in the terminal.';
      command.value = pair.installCommand;
      panel.hidden = false;
      copy.textContent = 'Copy command';
      script.value = '';
      script.parentElement.open = false;
      script.parentElement.ontoggle = async () => {
        if (!script.parentElement.open || script.value) return;
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
      bind('Replace setup command', async () => {
        await post('cancel-pairing', { token, id: pair.id });
        await newPair();
      }, failure);
      void waitForPair(pair.id).catch(() => {
        if (sessionStorage.getItem('pasta-pair') !== pair.id) return;
        status.textContent = failure;
        bind('Check pairing status', () => waitForPair(pair.id), failure);
      });
    }

    if (activePair) {
      bind('Get a new setup command', async () => {
        await post('cancel-pairing', { token, id: activePair });
        await newPair();
      }, failure);
      void waitForPair(activePair).catch(() => {
        status.textContent = failure;
        bind('Check pairing status', () => waitForPair(activePair), failure);
      });
    } else {
      bind('Get host setup command', newPair, 'Could not generate a setup command. Try again.');
    }
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
  details.textContent = 'Checking whether your owner passkey is registered…';
  async function chooseOwnerFlow() {
    const { enrolled } = await post('owner-state', {});
    if (enrolled) {
      title.textContent = 'Sign in to PaSTA';
      details.textContent = 'Use your passkey to continue setup or manage enrolled hosts.';
      bind('Sign in with passkey', async () => {
        const { id, options: optionsJSON } = await post('sign-in-options', {});
        const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
        const { token } = await post('sign-in', { id, response });
        hostSetup(token);
      }, 'Passkey sign-in didn’t complete. Try again.');
      return;
    }
    details.textContent = 'Enter your setup code to register the owner passkey.';
    setup.hidden = false;
    setup.onsubmit = event => {
      event.preventDefault();
      action.click();
    };
    bind('Continue', async () => {
      const token = tokenInput.value.trim();
      if (!token) {
        tokenInput.reportValidity();
        action.disabled = false;
        return;
      }
      const optionsJSON = await post('enrollment-options', { token });
      setup.hidden = true;
      tokenInput.value = '';
      title.textContent = 'Create your passkey';
      details.textContent = 'Use your device’s passkey prompt to set up PaSTA.';
      bind('Create passkey', async () => {
        const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
        const owner = await post('enroll', { token, response });
        hostSetup(owner.token);
      }, 'Passkey setup did not complete. You can retry or refresh for a new request.');
    }, 'That setup code did not work. Check the code and try again.');
  }
  void chooseOwnerFlow().catch(() => {
    status.textContent = 'Could not load setup. Try again.';
    bind('Retry', chooseOwnerFlow, 'Could not load setup. Try again.');
  });
} else {
  const job = new URLSearchParams(location.search).get('job');
  post('review-options', { job }).then(({ options: optionsJSON, job: request }) => {
    title.textContent = request.service ? 'Approve service restart'
      : request.dry_run ? 'Approve maintenance test' : 'Verify SSH enrollment';
    details.textContent = request.service
      ? 'Restart ' + request.service + ' once on ' + request.host + ' as ' + request.run_as +
        ', using the SSH account ' + request.execution_identity + '. The service may be briefly unavailable.'
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
