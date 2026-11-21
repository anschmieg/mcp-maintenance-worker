# Maintenance MCP Worker pilot

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

For deployment, set the runtime secret and configure a dedicated HTTPS route; `workers_dev` and preview URLs are off by default. No host networking or process execution is part of this service. Configure the Portal upstream with its documented `bearer` authentication mode. Test direct access first, then try the same two examples through OpenBot and the Portal. Do not remove endpoint authentication if the Portal fails to connect or relay the form.

## Runtime configuration

Use this repository as the source for changes. Keep live endpoints, host targets, fingerprints, and credentials in the runtime configuration of the component that consumes them.

- **Worker** — store `MCP_BEARER_TOKEN` as a Cloudflare Worker secret. Cloudflare CLI authentication belongs in the operator's local credential store.
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

Configure `PASSKEY_ORIGIN` as a stable HTTPS origin that routes both `/mcp` and `/passkeys/*` to the Worker. Use the exact origin with no trailing slash. Passkeys are scoped to that hostname. Generate a separate random setup code with at least 32 bytes of entropy and set it as the `PASSKEY_SETUP_TOKEN` Worker secret. Give it only to the owner through a private channel.

1. Open `/passkeys/onboard` and enter the setup code. Create your passkey and save it in your device's password manager. If you already registered the passkey, use **Continue host setup** with the same setup code.
2. Select **Sign in to Tailscale**. Open the Tailscale login link and add `openbot-tailnet-ssh-probe` to your tailnet. The wizard waits for the connection. If your tailnet requires device approval, approve the device in Tailscale **Machines**.
3. In **Add a pilot host**, select one of the devices visible to the Worker. If a machine is missing, check the probe's Tailscale policy or enter its Tailscale IPv4 address manually. The Worker does not need policy-write permission.
4. On the selected host, have an administrator create the dedicated unprivileged `openbot-tailnet-probe` SSH account. Select **Get host setup command**, then run the copied command from that account. It appends the restricted public key and sends the host fingerprint to the Worker over HTTPS using a short-lived, single-use pairing code. Use a POSIX shell, standard OpenSSH paths, and `curl` on the host. Review and approve the check when the page advances. The private probe pins the host key before requesting `openbot-enrollment-check-v1` on port 22. The page displays the result.
5. Repeat **Continue host setup** for each machine. Each new host gets a separate restricted SSH key. Once you finish pairing, remove `PASSKEY_SETUP_TOKEN`. The pilot supports one owner passkey. To revoke the Worker's access to a host or replace its pin, restore the owner-only setup secret if needed, open **Continue host setup**, and choose **Remove an enrolled host**. Removal blocks new checks and deletes the Worker's private key. A check already running can finish. Remove the old public key from the host's `authorized_keys` file as well. To reconnect the host, repeat pairing with the new key.

### Optional tagged enrollment

Before starting device sign-in, select **Set up a restricted Tailscale identity**. The wizard guides a tailnet administrator through adding `tag:openbot-probe` and creating an OAuth client with **Auth Keys Write** for that tag and optional **Devices Core Read** for the picker. Paste the credential into the wizard once. The Worker uses it to create a single-use tagged key and optionally load a 15-minute inventory, then discards the OAuth credential. If needed, add the displayed grant for the selected host on `tcp:22`. Check whether existing broader grants also apply to the tag. Operator-configured enrollment credentials still take precedence on a fresh installation. [Tailscale OAuth clients](https://tailscale.com/docs/features/oauth-clients) · [How grants combine](https://tailscale.com/docs/features/access-control/grants/grants-explained)

Add the following service binding to the maintenance Worker's deployment config:

```json
{
  "services": [
    {
      "binding": "HOST_PROBE",
      "service": "maintenance-tailnet-ssh-probe",
      "entrypoint": "HostVerifier"
    }
  ]
}
```

The probe's checked-in config disables `workers.dev` and preview URLs and defines no public route. Keep it private and deploy it before enabling the maintenance Worker's binding. If the Worker restarts with an outstanding check, the job is reported as having an unknown outcome and its consumed approval stays consumed. Correct any configuration problem and request another check with a new UUID. Use `maintenance_hosts` to list enrolled addresses and supply an address as `host` to `start_host_enrollment` or `maintenance_host_status`. Provisioning SSH users and installing keys remain administrator steps.

The browser calls use the locked SimpleWebAuthn package bundled with the Worker. Open the HTTPS review link from OpenBot in your browser. After the page confirms approval, close the tab and return to OpenBot to check the result. This flow works through an ordinary link and requires no OpenBot app changes.
