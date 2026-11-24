const title = document.querySelector('#title');
const details = document.querySelector('#details');
const setup = document.querySelector('#setup');
const tokenInput = document.querySelector('#token');
const action = document.querySelector('#action');
const status = document.querySelector('#status');
const steps = document.querySelector('#steps');

// Highlight a few common shell tokens while keeping the review text verbatim.
function renderCommand(code, command) {
  const tokens = /\\.|\x27[^\x27]*\x27|"(?:\\.|[^"\\])*"|(?<!\S)--?[a-zA-Z][\w-]*|\$(?:[a-zA-Z_]\w*|[0-9?#!@$*-])|[|&;<>]/gu;
  const fragment = document.createDocumentFragment();
  let offset = 0;
  for (const match of command.matchAll(tokens)) {
    const token = match[0];
    fragment.append(command.slice(offset, match.index));
    if (token.startsWith('\\')) {
      fragment.append(token);
    } else {
      const span = document.createElement('span');
      span.className = token.startsWith("'") || token.startsWith('"') ? 'shell-string'
        : token.startsWith('-') || token.startsWith('$') ? 'shell-argument'
          : 'shell-operator';
      span.textContent = token;
      fragment.append(span);
    }
    offset = match.index + token.length;
  }
  fragment.append(command.slice(offset));
  code.replaceChildren(fragment);
}

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
  if (!response.ok) throw Object.assign(new Error('Request rejected'), { status: response.status });
  return response.json();
}

function reviewStatus(tone, message) {
  status.dataset.tone = tone;
  const svgNamespace = 'http://www.w3.org/2000/svg';
  const icon = document.createElementNS(svgNamespace, 'svg');
  icon.setAttribute('class', 'status-icon');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('viewBox', '0 0 24 24');
  const path = document.createElementNS(svgNamespace, 'path');
  path.setAttribute('d', {
    success: 'M4 12l5 5L20 6',
    error: 'M12 8v5m0 3h.01 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
    warning: 'M12 6v6h4 M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
    pending: 'M5 12h.01m7 0h.01m7 0h.01',
  }[tone]);
  icon.append(path);
  const text = document.createElement('span');
  text.textContent = message;
  status.replaceChildren(icon, text);
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
      if (typeof failure === 'function') {
        await failure();
      } else {
        status.textContent = failure;
        action.disabled = false;
      }
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

  async function connect(loginWindow = null) {
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
        const tab = window.open('about:blank', '_blank');
        if (tab) {
          tab.opener = null;
          tab.document.title = 'PaSTA · Tailscale sign-in';
          tab.document.body.textContent = 'Waiting for Tailscale sign-in…';
        }
        try {
          await post('start-device-login', { token });
          await connect(tab);
        } catch (error) {
          try {
            if (tab && !tab.closed && tab.location.href === 'about:blank') tab.close();
          } catch { /* Leave an already-opened Tailscale tab available. */ }
          throw error;
        }
      }, 'Could not start Tailscale sign-in. Try again.');
      return;
    }
    taggedSetup.hidden = true;
    guide.hidden = true;
    for (let attempt = 0; result.state === 'tailnet_pending' && attempt < 60; attempt++) {
      if (result.loginUrl && loginWindow && !loginWindow.closed) {
        try { loginWindow.location.replace(result.loginUrl); }
        catch { loginWindow.close(); }
        loginWindow = null;
      }
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
    if (loginWindow && !loginWindow.closed) loginWindow.close();
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
    const cancelWaiting = document.querySelector('#cancel-waiting');
    const replaceFailed = document.querySelector('#replace-failed-pair');
    const activePair = sessionStorage.getItem('pasta-pair');
    let lastPairId = activePair;
    const failure = 'Could not check the pairing. Try again.';

    function clearSetupCommand() {
      command.value = '';
      copy.disabled = true;
      copy.onclick = null;
      panel.hidden = true;
      cancelWaiting.hidden = true;
    }

    async function waitForPair(pairId, retry = false) {
      replaceFailed.hidden = true;
      for (let attempt = 0; attempt < 360; attempt++) {
        if (sessionStorage.getItem('pasta-pair') !== pairId) return;
        const progress = await post('finish-host-pairing', { token, id: pairId, retry });
        retry = false;
        if (sessionStorage.getItem('pasta-pair') !== pairId) return;
        if (progress.state === 'verified') {
          sessionStorage.removeItem('pasta-pair');
          clearSetupCommand();
          title.textContent = 'Host paired and verified';
          details.textContent = progress.host + ' is ready for maintenance.';
          status.textContent = '';
          bind('Add another host', newPair, failure);
          return;
        }
        if (progress.state === 'verification_failed') {
          clearSetupCommand();
          const messages = {
            host_key_unverified: 'The SSH host key did not match. Check that OpenSSH is serving the key on this host.',
            ssh_authentication_failed: 'The host rejected the SSH key. Check SSH access for the account in the terminal.',
            diagnostic_failed: 'The SSH check returned an unexpected result. Check the account’s restricted key.',
            target_changed: 'This address already has a different enrollment. Check the enrolled host before retrying.',
          };
          status.textContent = messages[progress.failure] ?? 'PaSTA could not complete the SSH check. Check network access to port 22, then retry.';
          bind('Retry SSH verification', () => waitForPair(pairId, true), failure);
          replaceFailed.hidden = false;
          replaceFailed.onclick = async () => {
            replaceFailed.disabled = action.disabled = true;
            try {
              await replacePair(pairId);
            } catch {
              status.textContent = 'Could not discard the failed pairing. Try again.';
              action.disabled = false;
            } finally {
              replaceFailed.disabled = false;
            }
          };
          return;
        }
        if (['pairing_canceled', 'pairing_expired', 'unsupported_platform'].includes(progress.state)) {
          sessionStorage.removeItem('pasta-pair');
          clearSetupCommand();
          status.textContent = {
            pairing_canceled: 'Host pairing was canceled in the terminal.',
            pairing_expired: 'This command expired. Generate a fresh one to continue.',
            unsupported_platform: 'This computer cannot be paired. Generate a fresh setup command for a Linux host.',
          }[progress.state];
          bind('Get a new setup command', newPair, failure);
          return;
        }
        cancelWaiting.hidden = progress.state !== 'waiting_for_host';
        cancelWaiting.onclick = async () => {
          cancelWaiting.disabled = true;
          try {
            await discardPair(pairId);
            clearSetupCommand();
            status.textContent = 'Host setup canceled.';
            bind('Get a new setup command', newPair, failure);
          } catch {
            status.textContent = 'Could not cancel host setup. Try again.';
          } finally {
            cancelWaiting.disabled = false;
          }
        };
        status.textContent = progress.state === 'verifying' ? 'Verifying SSH on ' + (progress.host ?? 'the host') + '…'
          : progress.state === 'waiting_for_confirmation' ? 'Detected ' + (progress.host ?? 'the host') + '. Confirm pairing in the terminal.'
          : 'Waiting for you to run the setup command on a host.';
        await new Promise(resolve => setTimeout(resolve, 2500));
      }
      bind('Check pairing status', () => waitForPair(pairId), failure);
    }

    async function newPair() {
      replaceFailed.hidden = true;
      clearSetupCommand();
      status.textContent = 'Generating a fresh setup command…';
      const pair = await post('begin-host-pairing', { token });
      if (!pair.id || pair.id === lastPairId || !pair.installCommand) throw new Error('No fresh pairing command');
      lastPairId = pair.id;
      sessionStorage.setItem('pasta-pair', pair.id);
      title.textContent = 'Add a host';
      details.textContent = 'Copy the new setup command and run it on the Linux host you want to add.';
      command.value = pair.installCommand;
      panel.hidden = false;
      copy.textContent = 'Copy new setup command';
      copy.disabled = false;
      script.value = '';
      delete script.dataset.loaded;
      script.parentElement.open = false;
      script.parentElement.ontoggle = async () => {
        if (!script.parentElement.open || script.dataset.loaded === 'true') return;
        try {
          const response = await fetch('/passkeys/setup-preview');
          if (!response.ok) throw new Error();
          script.value = await response.text();
          script.dataset.loaded = 'true';
        } catch {
          script.value = 'Could not load the script preview. Close it and open it again to retry.';
        }
      };
      copy.onclick = async () => {
        if (sessionStorage.getItem('pasta-pair') !== pair.id) return;
        try {
          await navigator.clipboard.writeText(pair.installCommand);
          if (sessionStorage.getItem('pasta-pair') === pair.id) copy.textContent = 'New command copied';
        } catch {
          if (sessionStorage.getItem('pasta-pair') !== pair.id) return;
          command.select();
          copy.textContent = 'Copy selected command manually';
        }
      };
      bind('Replace setup command', () => replacePair(pair.id), failure);
      void waitForPair(pair.id).catch(() => {
        if (sessionStorage.getItem('pasta-pair') !== pair.id) return;
        status.textContent = failure;
        bind('Check pairing status', () => waitForPair(pair.id), failure);
      });
    }

    async function discardPair(pairId) {
      const result = await post('cancel-pairing', { token, id: pairId });
      if (result.state !== 'invalidated') throw new Error('Pairing was not discarded');
      if (sessionStorage.getItem('pasta-pair') === pairId) sessionStorage.removeItem('pasta-pair');
    }

    async function replacePair(pairId) {
      await discardPair(pairId);
      await newPair();
    }

    if (activePair) {
      bind('Get a new setup command', () => replacePair(activePair), failure);
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

async function startAdmin() {
  const dashboard = document.querySelector('#standing-rules');
  const form = document.querySelector('#standing-form');
  const clientChoices = document.querySelector('#standing-client');
  const hostChoices = document.querySelector('#standing-host');
  const commandSelect = document.querySelector('#standing-command');
  const addRule = document.querySelector('#add-rule');
  const matcherPanel = document.querySelector('#standing-matcher');
  const matchKind = document.querySelector('#standing-match-kind');
  const matchText = document.querySelector('#standing-match-text');
  const presetPanel = document.querySelector('#standing-preset');
  const decision = document.querySelector('#standing-decision');
  const categoryPanel = document.querySelector('#standing-category');
  const categorySelect = document.querySelector('#standing-category-value');
  let categoryLabels = Object.create(null);
  const preview = document.querySelector('#rule-preview');
  const test = document.querySelector('#test-request');
  const testClient = document.querySelector('#test-client');
  const testHost = document.querySelector('#test-host');
  const testResult = document.querySelector('#test-result');
  const testPanel = document.querySelector('#rule-test');
  const ruleNumbers = new Map();
  const pickers = [
    { list: clientChoices, search: document.querySelector('#filter-clients'), summary: document.querySelector('#selected-clients') },
    { list: hostChoices, search: document.querySelector('#filter-hosts'), summary: document.querySelector('#selected-hosts') },
  ];
  const decisions = { 'require-approval': 'Always ask', deny: 'Always deny', allow: 'Always allow' };

  function updateMatcher(value = decision.value) {
    const preset = matchKind.value === 'preset';
    const semantic = matchKind.value === 'semantic';
    matcherPanel.hidden = preset || semantic;
    matchText.required = !matcherPanel.hidden;
    categoryPanel.hidden = !semantic;
    categorySelect.required = semantic;
    presetPanel.hidden = !preset;
    commandSelect.required = preset;
    const choices = preset ? ['allow'] : ['require-approval', 'deny'];
    if (semantic && categorySelect.value === 'read-only') choices.push('allow');
    options(decision, 'Select a decision', choices.map(key => [key, decisions[key]]));
    decision.value = choices.includes(value) ? value : choices[0];
    updatePreview();
  }
  const save = form.querySelector('[type="submit"]');
  const cancel = document.querySelector('#cancel-rule');
  let editing;

  const diagnostics = {
    'read-only': 'All supported read-only checks',
    uptime: 'System uptime',
    'df -h /srv/techleaddocker': 'Docker storage usage',
  };
  const scopeLabel = command => command === 'read-only' ? diagnostics[command] : (diagnostics[command] + ' (' + command + ')');
  const hostName = host => host.name || host.address;
  const clientName = client => client.reportedName || client.name;
  const clientLabel = client => clientName(client) + ' · ' + client.id.slice(-6);
  const clientDetail = client => (client.reportedName ? 'Reported via MCP · ' : 'OAuth · ') + client.callback + ' · ' + client.id.slice(-6);

  function node(tag, text, className) {
    const element = document.createElement(tag);
    element.textContent = text;
    if (className) element.className = className;
    return element;
  }

  function identity(name, detail) {
    const cell = node('td', '', 'admin-identity');
    cell.append(node('strong', name));
    if (detail) cell.append(node('small', detail));
    return cell;
  }

  function pill(label, active) {
    const badge = node('span', label, 'admin-pill');
    badge.dataset.active = String(active);
    return badge;
  }

  function rowButton(label, target, callback) {
    const button = node('button', label, 'secondary');
    button.type = 'button';
    button.setAttribute('aria-label', label + ' · ' + target);
    button.onclick = callback;
    return button;
  }

  function row(parent, ...contents) {
    const item = node('tr', '');
    for (const content of contents) {
      if (content?.tagName === 'TD') item.append(content);
      else {
        const cell = node('td', typeof content === 'string' ? content : '');
        if (content && typeof content !== 'string') cell.append(content);
        item.append(cell);
      }
    }
    parent.append(item);
  }

  function options(select, prompt, entries) {
    select.replaceChildren(new Option(prompt, ''), ...entries.map(([value, label]) => new Option(label, value)));
  }

  function checkboxes(container, entries) {
    container.replaceChildren(...entries.map(([value, label]) => {
      const item = node('label', '');
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.value = value;
      item.append(checkbox, node('span', label));
      return item;
    }));
  }

  function checked(container) {
    return [...container.querySelectorAll('input:checked')].map(input => input.value);
  }

  function choose(container, selected) {
    for (const input of container.querySelectorAll('input')) input.checked = selected.includes(input.value);
  }

  function updatePreview() {
    const selected = pickers.map(({ list, search, summary }) => {
      const labels = [];
      for (const input of list.querySelectorAll('input')) {
        const label = input.parentElement;
        const name = label.textContent;
        label.hidden = !name.toLowerCase().includes(search.value.trim().toLowerCase());
        if (input.checked) labels.push(name);
      }
      summary.textContent = labels.length ? labels.join(', ') : 'None selected';
      return labels.join(' or ');
    });
    const semantic = matchKind.value === 'semantic';
    const condition = matchKind.value === 'preset'
      ? commandSelect.value && scopeLabel(commandSelect.value)
      : semantic ? categoryLabels[categorySelect.value] : matchText.value.trim() && (matchKind.value === 'exact' ? 'exactly matches ' : 'starts with ') + JSON.stringify(matchText.value);
    preview.textContent = selected.every(Boolean) && condition
      ? decisions[decision.value] + ' when ' + selected[0] + ' requests a command on ' + selected[1] +
        (matchKind.value === 'preset' || semantic ? ' matching ' : ' whose text ') + condition + '.'
      : 'Select clients, hosts, and a command match to preview this rule.';
  }

  form.addEventListener('input', updatePreview);
  matchKind.onchange = categorySelect.onchange = () => updateMatcher();

  function showEditor({ clientIds = [], hostAddresses = [], command, matcher, id } = {}) {
    editing = id;
    document.querySelector('#standing-form-title').textContent = id ? 'Edit rule' : 'Add rule';
    choose(clientChoices, clientIds);
    choose(hostChoices, hostAddresses);
    const readOnly = command === 'read-only';
    const preset = Boolean(command && !matcher && !readOnly);
    categorySelect.value = readOnly ? 'read-only' : matcher?.kind === 'semantic' ? matcher.text : '';
    commandSelect.value = preset ? command : '';
    matchKind.value = preset ? 'preset' : readOnly ? 'semantic' : matcher?.kind ?? 'semantic';
    for (const { search } of pickers) search.value = '';
    matchText.value = matcher?.text ?? '';
    updateMatcher(preset || readOnly ? 'allow' : command);
    form.hidden = false;
    status.textContent = '';
    const next = !checked(clientChoices).length ? clientChoices.querySelector('input') :
      !checked(hostChoices).length ? hostChoices.querySelector('input') : matchKind;
    form.scrollIntoView({ block: 'nearest' });
    next?.focus();
  }

  function closeEditor() {
    editing = undefined;
    form.hidden = true;
    addRule.focus();
  }

  function showTable(name, hasRows) {
    document.querySelector('#' + name + '-table').hidden = !hasRows;
    document.querySelector('#' + name + '-empty').hidden = hasRows;
  }

  async function loadDashboard() {
    const { clients, hosts, rules, commands, semanticLabels, sharedBearerConfigured } = await post('standing-rules', {});
    const activeClients = clients.filter(client => client.active);
    const eligibleHosts = hosts.filter(host => host.state === 'ready');
    const canAddRule = activeClients.length > 0 && eligibleHosts.length > 0;
    const clientRows = document.querySelector('#client-rows');
    const hostRows = document.querySelector('#host-rows');
    const ruleRows = document.querySelector('#standing-list');
    checkboxes(clientChoices, activeClients.map(client => [client.id, clientLabel(client)]));
    checkboxes(hostChoices, eligibleHosts.map(host => [
      host.address, host.name ? host.name + ' (' + host.address + ')' : host.address,
    ]));
    options(commandSelect, 'Select a diagnostic', commands.filter(command => Object.hasOwn(diagnostics, command))
      .map(command => [command, scopeLabel(command)]));
    categoryLabels = Object.assign(Object.create(null), semanticLabels);
    options(categorySelect, 'Select a parsed condition', Object.entries(categoryLabels));
    options(testClient, 'Select a client', activeClients.map(client => [client.id, clientLabel(client)]));
    options(testHost, 'Select a host', eligibleHosts.map(host => [host.address, hostName(host)]));
    testPanel.hidden = !canAddRule;
    testResult.hidden = true;
    addRule.disabled = !canAddRule;
    const emptyRules = document.querySelector('#rules-empty');
    emptyRules.textContent = canAddRule ? 'No rules yet.' : activeClients.length
      ? 'Pair a host with command access to create a rule.' : 'Connect an MCP client through OAuth to create a rule.';
    clientRows.replaceChildren();
    for (const client of clients) {
      row(clientRows, identity(clientName(client), [clientDetail(client),
        ...(client.reportedNames ?? []).filter(name => name !== clientName(client))].join(' · ')), pill(client.active ? 'Authorized' : 'Expired', client.active),
        client.active && canAddRule ? rowButton('Add rule', clientLabel(client), () => showEditor({ clientIds: [client.id] })) : null);
    }
    if (sharedBearerConfigured) {
      row(clientRows, identity('Shared bearer access', 'Bearer token'), pill('Approval required', false), null);
    }
    const emptyClients = document.querySelector('#clients-empty');
    emptyClients.textContent = sharedBearerConfigured ? 'No OAuth connections recorded yet. Connect PaSTA from your MCP client and make a request.' : emptyClients.textContent;
    showTable('clients', clients.length > 0 || sharedBearerConfigured);
    emptyClients.hidden = clients.length > 0;

    hostRows.replaceChildren();
    for (const host of hosts) {
      const ready = host.state === 'ready';
      const access = ready ? 'Rule eligible' : host.state === 'removing' ? 'Removal pending' : 'Approval only';
      row(hostRows, identity(hostName(host), host.name ? host.address : ''), node('code', host.account), pill(access, ready),
        ready && canAddRule ? rowButton('Add rule', hostName(host), () => showEditor({ hostAddresses: [host.address] })) : null);
    }
    showTable('hosts', hosts.length > 0);

    ruleRows.replaceChildren();
    ruleNumbers.clear();
    for (const [index, rule] of rules.entries()) {
      ruleNumbers.set(rule.id, index + 1);
      const clientNames = rule.grants.map(grant => {
        const client = clients.find(item => item.id === grant);
        return client ? clientLabel(client) : 'Unlisted client · ' + grant.slice(-6);
      });
      const hostNames = rule.addresses.map(address => {
        const host = hosts.find(item => item.address === address);
        return host ? hostName(host) : address;
      });
      const controls = node('span', '', 'admin-actions');
      const label = clientNames.join(', ') + ' on ' + hostNames.join(', ') + ' · ' + rule.command;
      if (canAddRule) controls.append(rowButton('Edit', label, () => showEditor(rule)));
      for (const [offset, title] of [[-1, 'Move up'], [1, 'Move down']]) {
        if (index + offset < 0 || index + offset >= rules.length) continue;
        controls.append(rowButton(title, label, async event => {
          const button = event.currentTarget;
          button.disabled = true;
          try {
            await post('move-standing-rule', { id: rule.id, direction: offset });
            await loadDashboard();
            reviewStatus('success', 'Rule order saved.');
          } catch {
            button.disabled = false;
            reviewStatus('error', 'Could not move the rule. Refresh and try again.');
          }
        }));
      }
      controls.append(rowButton('Revoke', label, async event => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
          await post('remove-standing-rule', { id: rule.id });
          if (editing === rule.id) closeEditor();
          await loadDashboard();
          reviewStatus('success', 'Rule revoked.');
        } catch {
          button.disabled = false;
          reviewStatus('error', 'Could not revoke the rule. Refresh and check the rule.');
        }
      }));
      const memberList = labels => {
        const cell = node('td', '', 'admin-members');
        for (const item of labels) cell.append(node('span', item));
        return cell;
      };
      const fullyAvailable = rule.clientIds.length === rule.grants.length && rule.hostAddresses.length === rule.addresses.length;
      const commandMatch = rule.matcher
        ? rule.matcher.kind === 'semantic' ? categoryLabels[rule.matcher.text] :
          identity(rule.matcher.kind === 'exact' ? 'Exact text' : 'Starts with', rule.matcher.text)
        : rule.approvedCommands ? identity('Supported read-only checks', rule.approvedCommands.join(' · ')) : scopeLabel(rule.command);
      row(ruleRows, String(index + 1), memberList(clientNames), memberList(hostNames), commandMatch,
        decisions[rule.matcher ? rule.command : 'allow'],
        pill(fullyAvailable ? 'Active' : rule.available ? 'Partial' : 'Unavailable', fullyAvailable), controls);
    }
    showTable('rules', rules.length > 0);

    details.textContent = 'Manage access rules, MCP clients, and SSH hosts.';
    document.querySelector('#admin-nav').hidden = false;
    dashboard.hidden = false;
    action.hidden = true;
  }

  test.oninput = () => { testResult.hidden = true; };
  test.onsubmit = async event => {
    event.preventDefault();
    const submit = test.querySelector('button');
    submit.disabled = true;
    testResult.hidden = false;
    testResult.textContent = 'Evaluating…';
    try {
      const { decision: result, matches, categories, error } = await post('preview-standing-rules', {
        grant: testClient.value,
        address: testHost.value,
        command: document.querySelector('#test-command').value,
      });
      const rows = matches?.map(id => ruleNumbers.get(id)).filter(Boolean).sort((a, b) => a - b);
      testResult.textContent = error ?? (decisions[result] + '. ' +
        (rows.length ? 'Matching rules: ' + rows.join(', ') + '.' : 'No saved rules matched.') +
        (categories.length ? ' Parsed as: ' + categories.map(category => (categoryLabels[category] ?? category)).join(', ') + '.' : ''));
    } catch {
      testResult.textContent = 'Could not evaluate the request. Refresh the dashboard and try again.';
    } finally {
      submit.disabled = false;
    }
  };

  addRule.onclick = () => showEditor();
  cancel.onclick = closeEditor;
  form.onsubmit = async event => {
    event.preventDefault();
    const grants = checked(clientChoices);
    const addresses = checked(hostChoices);
    if (!grants.length || !addresses.length) {
      reviewStatus('error', 'Select at least one MCP client and one SSH host.');
      (grants.length ? hostChoices : clientChoices).querySelector('input')?.focus();
      return;
    }
    save.disabled = true;
    try {
      await post('add-standing-rule', {
        grants, addresses, command: decision.value === 'allow' ? (presetPanel.hidden ? 'read-only' : commandSelect.value) : decision.value,
        id: editing,
        matcher: decision.value === 'allow' ? undefined : {
          kind: matchKind.value, text: categoryPanel.hidden ? matchText.value : categorySelect.value,
        },
      });
      await loadDashboard();
      closeEditor();
      reviewStatus('success', 'Rule saved.');
    } catch {
      reviewStatus('error', 'Could not save the rule. Check that the connection and host are still available and the rule is unique.');
    } finally {
      save.disabled = false;
    }
  };

  try {
    await loadDashboard();
  } catch (error) {
    action.hidden = false;
    if (error.status === 403) {
      details.textContent = 'Sign in with your owner passkey to manage connections and standing approvals.';
      bind('Sign in with passkey', async () => {
        const { id, options: optionsJSON } = await post('sign-in-options', {});
        const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
        await post('sign-in', { id, response });
        await loadDashboard();
      }, 'Sign-in did not complete. Try again.');
    } else {
      details.textContent = 'PaSTA could not load the dashboard.';
      bind('Retry', startAdmin, 'PaSTA could not load the dashboard. Try again.');
    }
  }
}

if (location.pathname.endsWith('/admin')) {
  void startAdmin();
} else if (location.pathname.endsWith('/onboard')) {
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
  let token;
  const deadline = document.querySelector('#review-deadline');
  const commandPanel = document.querySelector('#review-command');

  function showCommand(request) {
    if (!request.command) return;
    title.textContent = 'Approve command';
    details.textContent = '';
    details.hidden = true;
    const commandDisplay = document.querySelector('#command-display');
    renderCommand(commandDisplay.querySelector('code'), request.command);
    commandDisplay.hidden = false;

    const hostname = request.host_name?.replace(/\.[^.]+\.ts\.net\.?$/iu, '');
    const target = commandPanel.querySelector('[data-review="host"]');
    target.textContent = request.execution_identity + ' @ ' + (hostname || request.host);
    target.title = hostname ? request.host_name + ' · ' + request.host : '';
    const runAs = commandPanel.querySelector('[data-review="run-as"]');
    runAs.hidden = !request.run_as;
    runAs.textContent = request.run_as ? 'Runs as ' + request.run_as : '';
    commandPanel.querySelector('[data-review="explanation"]').textContent = request.explanation;
    const statement = commandPanel.querySelector('[data-review="statement"]');
    statement.textContent = request.statement ?? '';
    statement.parentElement.hidden = !request.statement;
    commandPanel.hidden = false;
  }

  const results = {
    verified_dry_run: ['success', 'Passkey approval verified for the dry run.'],
    verified: ['success', 'Host enrollment verified.'],
    service_restarted: ['success', 'Service restarted.'],
    expired: ['warning', 'This request expired. Ask your agent for a new approval link.'],
    checking_host: ['pending', 'Approval verified. The host operation is still running.'],
    check_outcome_unknown: ['warning', 'The outcome is unknown. Check the host before retrying.'],
    target_changed: ['error', 'The enrolled host changed. Ask your agent for a new approval request.'],
    host_key_unverified: ['error', 'The SSH host key could not be verified.'],
    ssh_authentication_failed: ['error', 'The host rejected the SSH login.'],
    unconfigured: ['error', 'SSH access has not been configured for this host.'],
    diagnostic_failed: ['error', 'The SSH diagnostic failed.'],
    command_completed: ['success', 'Command completed successfully.'],
    command_failed: ['error', 'The command exited with an error.'],
    restart_failed: ['error', 'The service restart failed.'],
    connection_failed: ['error', 'PaSTA could not connect to the host.'],
    unknown: ['error', 'PaSTA could not find this request. Check the link with your agent.'],
  };

  function showResult(result) {
    showCommand(result);
    deadline.hidden = true;
    action.hidden = true;
    if (result.command && (result.state === 'verified' || result.state === 'service_restarted')) {
      reviewStatus('success', 'Command completed successfully.');
      return;
    }
    reviewStatus(...(results[result.state] ?? ['error', 'PaSTA could not read the result. Reload this page to check again.']));
    if (result.can_reconcile) {
      action.hidden = false;
      bind('I checked the host. Allow a new request', async () => {
        await post('reconcile', { job, token });
        action.hidden = true;
        reviewStatus('success', 'Host check recorded. A new request still needs passkey approval.');
      }, 'PaSTA could not record the host check. Reload and try again.');
    }
  }

  async function loadReview() {
    action.hidden = false;
    let review;
    try {
      review = await post('review-options', { job, token });
    } catch {
      const result = await post('job-status', { job, token }).catch(() => null);
      if (result && result.state !== 'pending') {
        showResult(result);
      } else {
        reviewStatus('error', 'PaSTA could not load this request. Check the link or try again.');
        bind('Retry', loadReview, 'PaSTA could not load this request.');
      }
      return;
    }
    const { options: optionsJSON, job: request } = review;
    title.textContent = request.command && !request.service ? 'Approve SSH command'
      : request.service ? 'Approve service restart'
      : request.dry_run ? 'Approve maintenance test' : 'Verify SSH enrollment';
    details.textContent = request.command && !request.service
      ? 'Run this Bash command once over SSH with the access of the account shown below.'
      : request.service
      ? 'Restart ' + request.service + ' once on ' + request.host + ' as ' + request.run_as +
        ', using the SSH account ' + request.execution_identity + '. The service may be briefly unavailable.'
      : request.dry_run
      ? request.operation + ' on ' + request.host + ' as ' + request.execution_identity + '. This dry run will not connect to the host.'
      : 'Verify the SSH host key and run a read-only diagnostic on ' + request.host + ' as ' + request.execution_identity + '.';

    showCommand(request);
    const expires = new Date(request.expires_at);
    deadline.textContent = 'Approval deadline ' + new Intl.DateTimeFormat(undefined, {
      dateStyle: 'medium', timeStyle: 'short',
    }).format(expires);
    deadline.hidden = false;
    reviewStatus('pending', 'Waiting for your passkey approval.');
    bind(request.service ? 'Approve restart with passkey' : 'Approve with passkey', async () => {
      const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
      let result = await post('approve', { job, token, response });
      action.hidden = true;
      deadline.hidden = true;
      for (let attempt = 0; result.state === 'checking_host' && attempt < 30; attempt++) {
        reviewStatus('pending', request.service ? 'Approval verified. Restarting the service…' : 'Approval verified. Checking SSH enrollment…');
        await new Promise(resolve => setTimeout(resolve, 1000));
        result = await post('job-status', { job, token }).catch(() => result);
      }
      showResult(result);
    }, async () => {
      const result = await post('job-status', { job, token }).catch(() => null);
      if (result && result.state !== 'pending') {
        showResult(result);
      } else {
        reviewStatus('error', 'Passkey approval did not complete. Try again.');
        action.disabled = false;
      }
    });
  }

  if (/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/u.test(job ?? '')) {
    title.textContent = 'Open approval request';
    action.hidden = true;
    async function checkReviewSession() {
      const { signedIn, availability } = await post('review-session', { job });
      if (availability !== 'pending') {
        action.hidden = true;
        details.textContent = '';
        if (availability === 'answered') {
          reviewStatus('error', 'This approval request has already been answered.');
        } else {
          showResult({ state: availability });
        }
        return;
      }
      if (signedIn) return loadReview();
      details.textContent = 'Sign in with your passkey to view the request.';
      action.hidden = false;
      bind('Sign in with passkey', async () => {
        const { id, options: optionsJSON } = await post('sign-in-options', {});
        const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON });
        ({ token } = await post('sign-in', { id, response }));
        await loadReview();
      }, 'Sign-in did not complete. Try again.');
    }
    void checkReviewSession().catch(() => {
      action.hidden = false;
      bind('Retry', checkReviewSession, 'PaSTA could not load this request.');
      reviewStatus('error', 'PaSTA could not load this request.');
    });
  } else {
    showResult({ state: 'unknown' });
  }
}
