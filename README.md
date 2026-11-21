# Maintenance screening MCP — dry-run PoC

`screen_maintenance_command` accepts `{ "command": "..." }`. It uses the `mvdan/sh` Bash parser, then applies exact literal-argument rules. `uptime` and `df -h /srv/techleaddocker` are example `auto_candidate` rules, not a Docker runner design. Everything outside the narrow rule set goes to review, except blank, oversized or syntactically invalid input. Automatic classification accepts only the exact arguments separated by ASCII spaces or tabs. Quotes, comments, terminators, and newlines require review. Hidden control and Unicode formatting characters are invalid.

A review starts `elicitation/create` in form mode on the active `tools/call`. The form includes the request ID, reason and escaped input. The result distinguishes `accepted_test`, `not_confirmed`, `declined`, `dismissed`, and `elicitation_unavailable` (including unsupported clients or a timed-out/failed form). It never authorizes a host action, and every result includes `executed: false`. No command runner, host credentials, SSH, Docker connection or mount is implemented. A client can simulate every elicitation response. The Worker rejects extra tool arguments and always returns `approval_verified: false` and `execution_authorized: false`, including for `accepted_test`. A verified approval requires a separate trust mechanism before any executor is connected. Do not submit secrets or sensitive command text.

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

- **Optional Tailnet probe** — provide `PROBE_TOKEN`, `TS_AUTHKEY`, `PROBE_TARGET`, `PROBE_HOST_FINGERPRINT`, and `PROBE_SSH_KEY` as secrets on the isolated probe deployment.
- **GitHub Actions** — tests use a generated local bearer token. Release publication uses GitHub's per-run token. Production credentials are unnecessary for either job.

## Dependency releases

The Worker uses exact npm versions and `worker/package-lock.json`. Go uses `go.mod` and `go.sum`. GitHub Actions checks direct Go and npm dependencies daily and on manual dispatch. If the manifests change, it installs the candidate set and runs Go tests, the WebAssembly build, and local Worker MCP tests. A successful run commits only the tested manifests and publishes a GitHub release tagged to that commit. Publishing stops if the branch moved during validation. Releases do not deploy to Cloudflare.

The local tests use no production credentials. They cover screening, syntax facts, elicitation, detached timing probes, and passkey-to-SSH enrollment. The enrollment test uses a second local Worker with the production Undershell code and a disposable loopback SSH server. It checks the pinned fingerprint, the exact forced-command response, expired and replayed approvals, and recovery after a Worker restart with an SSH outcome still outstanding. Live Clef, passkeys on an owner's device, and Tailscale connectivity are separate integration checks.

The optional `experiments/tailnet` probe pins Undershell in an npm lockfile and `tailnet-do` to a Git commit, including its pinned Tailscale submodule. The update workflow builds and bundles that probe against candidate revisions. Tailnet enrollment and host authentication require a separately scoped live test. Only its private RPC entry point can request the fixed diagnostic.

## Fixed SSH diagnostic pilot

`experiments/tailnet/openbot-enrollment-check` is the host entry point for OpenSSH hosts with a POSIX shell. An administrator installs it at a root-owned executable path such as `/usr/local/libexec/openbot-enrollment-check`. Use a dedicated unprivileged account without sudo or password login. Authorize the pilot's Ed25519 public key with this entry in the account's authorized keys file:

```text
restrict,command="/usr/local/libexec/openbot-enrollment-check" ssh-ed25519 PUBLIC_KEY
```

Keep the account's authorized keys and forced command under administrator control. Scope the Worker tailnet identity to SSH on the pilot host. Configure the Worker with the pinned host fingerprint and the dedicated private key through runtime secrets. The SSH request must supply exactly `openbot-enrollment-check-v1`. The host handler returns one line containing `openbot-host-ready-v1` and exits with status zero. The POSIX implementation uses shell built-ins. A non-POSIX host needs a restricted handler for the same request and response. The Worker accepts LF and CRLF line endings.

Before connecting a real SSH job, bind approval to the job ID, target, operation, approved execution identity, and expiry. Persist consumption before opening SSH. If the outcome is unknown after starting SSH, keep that state for status queries and require a fresh approval before another attempt.

## Owner passkey setup and approval dry run

Configure `PASSKEY_ORIGIN` as a stable HTTPS origin that routes both `/mcp` and `/passkeys/*` to the Worker. Use the exact origin with no trailing slash. Passkeys are scoped to that hostname. Generate a separate random setup code with at least 32 bytes of entropy and set it as the `PASSKEY_SETUP_TOKEN` Worker secret. Give it only to the owner through a private channel.

1. On the owner's device, open `/passkeys/onboard` on that origin. Enter the setup code and select **Create passkey**. Save the passkey in the device's password manager. The Worker stores the credential's public key and accepts only the first successful enrollment. Remove `PASSKEY_SETUP_TOKEN` once enrollment succeeds. This pilot supports one owner credential and has no self-service recovery.
2. Call `start_passkey_test` with a fresh UUID and open the review URL on the owner's device. It displays the fixed job and asks for a passkey. After approving, query `passkey_test_status` with the same UUID, including from a new MCP session. This tests approval only. The status reports `executed: false`.
3. To enroll the pilot host, a host administrator installs the forced command and adds the public key to the dedicated `openbot-tailnet-probe` account. Configure the isolated Tailnet probe with that private key, the host endpoint and the verified SSH fingerprint, using runtime secrets. Restrict its Tailnet identity to TCP port 22 on `ams`. Add the RPC service binding below to the maintenance Worker deployment config.
4. Call `start_host_enrollment` with a fresh UUID and approve its review page with your passkey. The probe checks the pinned SSH host key, logs into the dedicated account, and requests the fixed `openbot-enrollment-check-v1` diagnostic once. Use `passkey_test_status` to read its output and exit status or `maintenance_host_status` to see the most recent completed check for `ams`.

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

The probe's checked-in config disables `workers.dev` and preview URLs and defines no public route. Keep it private and deploy it before enabling the maintenance Worker's binding. If the Worker restarts with an outstanding check, the job is reported as having an unknown outcome and its consumed approval stays consumed. Correct any configuration problem and request another check with a new UUID. This flow enrolls one predefined host. Provisioning SSH users and installing keys remain administrator steps.

The browser calls use the locked SimpleWebAuthn package bundled with the Worker. Open the HTTPS review link from OpenBot in your browser. After the page confirms approval, close the tab and return to OpenBot to check the result. This flow works through an ordinary link and requires no OpenBot app changes.
