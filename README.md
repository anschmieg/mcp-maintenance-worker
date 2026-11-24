# PaSTA

**Passkey-Approved SSH Tool for Agents** provides passkey-approved host maintenance over MCP. PaSTA connects over Tailscale today. OpenBot is one supported MCP client.

`screen_maintenance_command` accepts `{ "command": "..." }`. It uses the `mvdan/sh` Bash parser, then applies exact literal-argument rules. `uptime` and `df -h /srv/techleaddocker` are example `auto_candidate` rules, not a Docker runner design. Everything outside the narrow rule set goes to review, except blank, oversized or syntactically invalid input. Automatic classification accepts only the exact arguments separated by ASCII spaces or tabs. Quotes, comments, terminators, and newlines require review. Hidden control and Unicode formatting characters are invalid.

A review starts `elicitation/create` in form mode on the active `tools/call`. The form includes the request ID, reason and escaped input. The result distinguishes `accepted_test`, `not_confirmed`, `declined`, `dismissed`, and `elicitation_unavailable` (including unsupported clients or a timed-out/failed form). It never authorizes a host action, and every result includes `executed: false`. A client can simulate every elicitation response. The separate [onboarding pilot](#pilot-onboarding) can run one fixed check over restricted SSH after a passkey approval. The Worker rejects extra tool arguments and always returns `approval_verified: false` and `execution_authorized: false`, including for `accepted_test`. Do not submit secrets or sensitive command text.

## Local

Go 1.26+ (use a patched release):

```sh
go test -v ./...
go build -o maintenance-poc .
./maintenance-poc --http
```

The default Streamable HTTP endpoint is `http://127.0.0.1:8765/mcp`. Run `./maintenance-poc` without arguments for MCP stdio. The integration tests start an HTTP server and a real MCP SDK client. Its elicitation handler simulates the different responses; it is not a human or portal test.

## Coolify via Git

1. Import this directory as the repository root of a private Git repo. In Coolify, use the Dockerfile build pack and container port `8765`.
2. Put it behind HTTPS. Set `MCP_BEARER_TOKEN` as a runtime secret (generate a random value of at least 32 bytes). Do not put it in Git or forward it into a model prompt. A non-loopback bind refuses to start without a token. Do not mount Docker sockets or host volumes. Run one replica for this PoC: MCP sessions live in memory. If a health probe is required, use TCP rather than an unauthenticated HTTP request to `/mcp`.
3. The HTTP client needs to send the upstream `Authorization: Bearer …` header on all MCP requests. Keep streaming and the `Mcp-Session-Id` header intact through the proxy. Allow at least 90 seconds for a form response. First test OpenBot connected directly; then add the same server to the Cloudflare MCP Portal only if the portal can authenticate to the upstream and relay elicitation on this path. Do not remove authentication to make the portal connect. The statically configured bearer token is only a PoC access control, not a per-agent identity or approver credential.
4. From each route, try `uptime` (no form) and `uptime | wc` (form). Test submit with the checkbox checked, decline, and dismiss in separate calls. Verify the result refers to the displayed request ID and `executed` stays false. If the form cannot be relayed, record that path as unsupported/unverified rather than substituting approval in chat.

## Cloudflare Worker (serverless)

`worker/` uses Cloudflare Agents SDK and a Durable Object to keep the MCP session and its pending elicitation together. Both the Go server and the Worker build the same `internal/screen` package; the Worker calls it through Go WebAssembly. Use Node 22+ and Go 1.26+.

```sh
cd worker
npm ci
sh build.sh
npx wrangler deploy --dry-run
```

For a local test, set `MCP_BEARER_TOKEN` in `worker/.dev.vars` (random secret, at least 32 bytes; ignored by Git) and run `npx wrangler dev --port 8795`. Set the same variable securely for the test process and run `node test.mjs` in another shell. Do not reuse the local test secret for a deployed service. The test exercises the live local Worker with an MCP SDK client, including all form results, and checks unauthenticated requests. It does not simulate the Portal or prove OpenBot renders the form.

The Worker sends only commands classified as `review` to the Cloudflare Workers AI binding for a Clef Flash impact assessment. The model receives the submitted command text, the deterministic screening reason, and syntax facts from the same Bash parse. These facts describe structure such as a pipeline or redirection and do not determine runtime effects. The categories distinguish diagnostics, bounded scratch writes, sensitive reads, consequential changes, and uncertain effects. Its result is advisory and is returned beside the deterministic decision. Elicitation proceeds independently and a missing, invalid, or slow model response is marked `unavailable`. Set `REQUIRE_MODEL_ASSESSMENT=1` for MCP tests against a deployment with Workers AI available.

`start_timing_probe` and `timing_probe_status` exercise asynchronous orchestration without starting a process. A Durable Object alarm completes a no-op 5–300 seconds after submission. Retry with the same UUID and delay to keep the original deadline. `node test-timing.mjs` closes and reopens MCP sessions, checks replay and verifies eventual completion (`PROBE_SECONDS=70` tests beyond one minute). It does not verify a machine-side runner, job cancellation, or recovery from host reboot.

The default public Worker is named `pasta` and uses `pasta.<account-subdomain>.workers.dev`. You can also configure a dedicated HTTPS route. Preview URLs are disabled. The screening tool is a dry run. Configure the Portal upstream with its documented `bearer` authentication mode. Test direct access first, then try the same two examples through OpenBot and the Portal. Do not remove endpoint authentication if the Portal fails to connect or relay the form.

For a fresh Cloudflare deployment, set `PASTA_WORKERS_SUBDOMAIN` to your account’s Workers subdomain and run `bash scripts/deploy-pasta.sh`. The deploy command builds both Workers, generates the setup code and MCP credential if they were omitted, and shows the setup link and owner-only file that holds the code. A fresh deployment may take the credentials from `PASSKEY_SETUP_TOKEN` and `MCP_BEARER_TOKEN` instead. Set `PASSKEY_ORIGIN` when you configure a custom route. The script reuses the saved configuration on redeploy. It deploys the private SSH backend before the public Worker and verifies the service binding. Set `PASTA_REQUIRE_CONNECTED=1` when releasing to an already enrolled production deployment to require a live Tailscale connection.

## Runtime configuration

Use this repository as the source for changes. Keep live endpoints, host targets, fingerprints, and credentials in the runtime configuration of the component that consumes them.

- **Worker** — store `MCP_BEARER_TOKEN` as a Cloudflare Worker secret. Cloudflare CLI authentication belongs in the operator's local credential store.
- **OpenBot remote MCP** — use the production URL ending in `/mcp` as an HTTP server with no custom authorization header. When OpenBot asks you to sign in, use the owner passkey you registered during setup. PaSTA supports OAuth authorization code with S256 PKCE and accepts OpenBot's loopback callbacks. `OAUTH_REDIRECT_URI` also allows one exact HTTPS callback. The OAuth access token lasts 15 minutes. OpenBot can renew it for up to seven days from sign-in, after which the owner signs in again. SSH command approval still requires a separate passkey confirmation.
- **OpenBot stdio adapter** — provide `MCP_WORKER_URL` and `MCP_BEARER_TOKEN` at startup. Node 22 can load them from an owner-readable file outside the checkout. Run the following from `worker/` after installing its locked dependencies.

  ```sh
  node --env-file=/path/to/private/adapter.env openbot-direct.mjs
  ```

- **Private Tailnet probe** — use the browser setup below, or preconfigure `TS_OAUTH_CLIENT_ID`, `TS_OAUTH_CLIENT_SECRET`, and `TS_DEVICE_TAG` on the private probe. A scoped, pre-created `TS_AUTHKEY` also remains an operator fallback. Store preconfigured credentials as Worker secrets.
- **GitHub Actions** — tests use a generated local bearer token. Release publication uses GitHub's per-run token. Production credentials are unnecessary for either job.

## Dependency releases

The Worker uses exact npm versions and `worker/package-lock.json`. Go uses `go.mod` and `go.sum`. GitHub Actions checks direct Go and npm dependencies daily and on manual dispatch. If the manifests change, it installs the candidate set and runs Go tests, the WebAssembly build, and local Worker MCP tests. A successful run commits only the tested manifests and publishes a GitHub release tagged to that commit. Publishing stops if the branch moved during validation. Releases do not deploy to Cloudflare.

The local tests use no production credentials. They cover screening, syntax facts, elicitation, detached timing probes, and passkey-to-SSH enrollment. The enrollment test uses a second local Worker with the production Undershell code and a disposable loopback SSH server. It checks the pinned fingerprint, the exact forced-command response, expired and replayed approvals, and recovery after a Worker restart with an SSH outcome still outstanding. Live Clef, passkeys on an owner's device, and Tailscale connectivity are separate integration checks.

The optional `experiments/tailnet` probe pins Undershell in an npm lockfile and `tailnet-do` to a Git commit, including its pinned Tailscale submodule. The update workflow builds and bundles that probe against candidate revisions. Tailnet enrollment and host authentication require a separately scoped live test. Only its private RPC entry point can request the fixed diagnostic.

## Pilot onboarding

By default the private probe joins as a regular Tailscale device through Tailscale's browser sign-in. **The Worker inherits the network access your tailnet policy grants to devices signed in as you.** SSH pairing still grants access only to the configured host account, but it does not limit what the Worker can reach on the network. Use tagged enrollment if you need a dedicated network identity with SSH-only access. [Tailscale device visibility](https://tailscale.com/docs/concepts/device-visibility)

Configure `PASSKEY_ORIGIN` as a stable HTTPS origin that routes `/mcp`, `/passkeys/*`, and `/setup` to the Worker. Use the exact origin with no trailing slash. Passkeys are scoped to that hostname. Generate a separate random setup code with at least 32 bytes of entropy and set it as the `PASSKEY_SETUP_TOKEN` Worker secret. Give it only to the owner through a private channel.

1. Open `/passkeys/onboard` and enter the setup code to register the owner passkey. On later visits, select **Sign in with passkey**.
2. Select **Sign in to Tailscale**. Open the Tailscale login link and add the `pasta-mcp-worker` device. If your tailnet requires device approval, approve the device in Tailscale **Machines**.
3. Select **Get host setup command**. Run the one-line command in a Linux terminal on the machine you want to add. PaSTA checks whether the machine is visible on the connected tailnet, then the terminal shows its name. Select **1** to use the dedicated `pasta-mcp` account, **2** to choose an existing login, **3** to inspect what setup installs, or **4** or Enter to cancel. An existing login can have sudo privileges and must have a nonzero user ID. PaSTA asks before installing the key for that login and uses its existing sudo policy. The command needs sudo, Tailscale, OpenSSH Server, and curl on the host. Keep it private until pairing completes.
4. PaSTA verifies the pinned host key and restricted SSH command during pairing. If verification fails, fix the reported issue and select **Retry SSH verification**. Select **Add another host** to generate the next command.

The installer queries OpenSSH's effective `AuthorizedKeysFile` for the selected account. It supports the standard home file and a root-managed `/etc/ssh/authorized_keys/%u` directory. If verification fails and you need to select a different account, choose **Start over with a new setup command**. This revokes the failed pairing's keys in PaSTA. Remove the stale PaSTA key from the file used by the failed installer.

After the owner registers, remove `PASSKEY_SETUP_TOKEN` if desired. Use the passkey to resume setup or remove enrolled hosts. Removal blocks new checks and deletes the Worker's private key. A check already running can finish. Remove the old public key from the host's `authorized_keys` file as well.

### Approve a service restart

A Linux administrator can enable the first maintenance operation by installing a root-owned systemd unit named `openbot-maintenance-demo.service` and authorizing the exact restart below. For an acceptance test, use this disposable unit in `/etc/systemd/system/openbot-maintenance-demo.service` and run `sudo systemctl daemon-reload`.

```ini
[Unit]
Description=PaSTA disposable maintenance service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/true
```

The restart uses non-interactive sudo. If the selected account needs permission, use `visudo` to install this rule under `/etc/sudoers.d/`. Replace `pasta-mcp` with the enrolled login if you chose an existing account. The installer leaves sudo policy to the host administrator.

```sudoers
pasta-mcp ALL=(root) NOPASSWD: /usr/bin/systemctl restart openbot-maintenance-demo.service
```

PaSTA requires a fresh passkey approval for each restart. Ask the MCP client to call `request_service_restart` and approve the host and unit shown in the review. The client can retrieve the result by job UUID with `passkey_test_status`.

### Request-time Bash commands

On hosts paired with the current installer, call `request_maintenance_command` with the host’s Tailscale IPv4, a fresh job UUID, the exact Bash command, and a short reason. The Worker verifies Bash syntax and uses Clef to describe likely effects. The owner’s passkey approves the stored command and SSH target once. The authenticated MCP status tool returns the exit status and bounded stdout and stderr. The owner signs in with a passkey before the review reveals command details. Keep secrets out of commands and reasons. Command details and output stop being served 24 hours after the approval deadline and are removed by background cleanup.

New enrollments default to the dedicated maintenance account. The approval Worker signs a 30-second authorization for the exact Bash command, account, address and enrollment. The SSH forced command sends it to a root-owned verification gate, which records the job ID before dropping privileges to the paired account. Setup requires Python 3, OpenSSL with Ed25519 support, and sudo. The separately configured fixed demo restart still uses its existing SSH rule.

To migrate an older dynamic enrollment, remove the old PaSTA key line from that account’s SSH authorized keys and remove the host from PaSTA before re-pairing. Removing the enrollment revokes Worker-side keys. Removing the host-side key line closes the legacy SSH entry point.

The installer restricts the OpenSSH key to the PaSTA forced command and disables forwarding and interactive login. The Worker holds the private SSH key. Dynamic commands also require an approval signature that the host validates separately. Use a dedicated non-root account with only the permissions it needs.

Existing enrollments keep their fixed operations. To enable request-time commands on an existing host, remove its enrollment and old authorized key, then run the current pairing wizard. If the result of a command is unknown, check the host before retrying.

### Standing approvals

The owner can view MCP connections and paired SSH hosts at `/passkeys/admin`. Use **Add rule** to select one or more authorized OAuth connections, one or more paired hosts, and a read-only scope. A rule applies to every selected connection–host pair. Existing OAuth connections appear after their next authenticated request. PaSTA displays the name clients report during MCP initialization and matches permissions by OAuth connection ID. Agents that share an OpenBot OAuth connection share its rules. OAuth refresh preserves the connection ID. A newly authorized connection has a new ID.

A rule can permit one supported check or all supported read-only checks. The rule records the exact approved commands when saved. The currently supported commands are `uptime` and `df -h /srv/techleaddocker`. PaSTA matches the verified OAuth connection, the current host enrollment, and the exact command before authorizing a single job. Other valid requests follow the normal passkey review flow. Use `passkey_test_status` to check the job outcome and see whether a standing rule authorized it.

### Optional tagged enrollment

Before starting device sign-in, select **Set up a restricted Tailscale identity**. The wizard guides a tailnet administrator through adding `tag:openbot-probe` and creating an OAuth client with **Auth Keys Write** for that tag. Paste the credential into the wizard once. The Worker uses it to create a single-use tagged key and then discards the OAuth credential. Allow the tag to reach the intended hosts on `tcp:22` so PaSTA can discover and verify them. Check whether existing broader grants also apply to the tag. Operator-configured enrollment credentials still take precedence on a fresh installation. [Tailscale OAuth clients](https://tailscale.com/docs/features/oauth-clients) · [How grants combine](https://tailscale.com/docs/features/access-control/grants/grants-explained)

Add the following service binding to the maintenance Worker's deployment config:

```json
{
  "services": [
    {
      "binding": "HOST_PROBE",
      "service": "pasta-ssh-backend",
      "entrypoint": "HostVerifier"
    }
  ]
}
```

The probe's checked-in config disables `workers.dev` and preview URLs and defines no public route. Keep it private and deploy it before enabling the maintenance Worker's binding. If the Worker restarts with an outstanding check, the job is reported as having an unknown outcome and its consumed approval stays consumed. Correct any configuration problem and request another check with a new UUID. Use `maintenance_hosts` to list enrolled addresses and supply an address as `host` to `start_host_enrollment` or `maintenance_host_status`. The one-line installer provisions the restricted SSH account and key. The host must already run Tailscale and OpenSSH Server.

The browser calls use the locked SimpleWebAuthn package bundled with the Worker. Open the HTTPS review link from your MCP client in your browser. After the page confirms approval, close the tab and return to your MCP client to check the result. This flow works through an ordinary link and requires no OpenBot app changes.
