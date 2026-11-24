import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InitializeRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { classify } from './classify';
import { assessCommand } from './assessment';
import { TimingProbe } from './timing';
import { approvalStore, passkeyOrigin, passkeyRoute } from './passkeys';
import { authenticatedOAuthGrant, oauthRoute, oauthUnauthorized, type OAuthEnv } from './oauth';
export { OAuthGrant } from './oauth';
export { TimingProbe };
export { PasskeyApproval } from './passkeys';
type Env = OAuthEnv & { PROBES: DurableObjectNamespace<TimingProbe> };

const grantHeader = 'x-pasta-verified-oauth-grant';

const approvalInstructions = 'When a PaSTA tool returns review_url, immediately give the user that exact URL as a clickable approval link in chat. Wait for the owner to approve, then use passkey_test_status with the original job_id to check the result. A pending request has not run.';

export class MaintenanceAgent extends McpAgent<Env> {
  server = new McpServer({name:'pasta',version:'0.6.0'}, { instructions: approvalInstructions });
  async init() {
    const probe_id=z.string().uuid();
    const output=(probe:unknown)=>({content:[{type:'text' as const,text:JSON.stringify(probe)}],structuredContent:{probe,executed:false}});
    if (passkeyOrigin(this.env)) {
      const jobSchema = { job_id: z.string().uuid().toLowerCase() };
      const result = (job: Record<string, unknown>) => ({
        content: [
          { type: 'text' as const, text: JSON.stringify(job) },
          ...(typeof job.review_url === 'string' ? [{
            type: 'text' as const,
            text: 'Send this link to the user now: [Approve in PaSTA](' + job.review_url + '). Wait for the owner to approve before checking the job result.',
          }] : []),
        ],
        structuredContent: job,
      });
      this.server.registerTool('start_passkey_test', {
        description: 'Create a dry-run approval for a fixed enrollment diagnostic. No host action runs. ' + approvalInstructions,
        inputSchema: jobSchema,
      }, async ({ job_id }) => result(await approvalStore(this.env).start(job_id)));
      this.server.registerTool('passkey_test_status', {
        description: 'Read the approval and execution result by its original job UUID. ' + approvalInstructions,
        inputSchema: jobSchema,
      }, async ({ job_id }) => result(await approvalStore(this.env).status(job_id)));
      this.server.registerTool('start_host_enrollment', {
        description: 'Request passkey approval to run the fixed openbot-enrollment-check-v1 SSH diagnostic for an enrolled host. Specify the Tailscale IPv4 when more than one host is enrolled. ' + approvalInstructions,
        inputSchema: { ...jobSchema, host: z.string().optional() },
      }, async ({ job_id, host }) => result(await approvalStore(this.env).start(job_id, true, host)));
      this.server.registerTool('maintenance_connection', {
        description: 'Show the authenticated OAuth connection ID for configuring standing rules in PaSTA.',
        inputSchema: {},
      }, async (_args, extra) => {
        const grant = extra.requestInfo?.headers[grantHeader];
        return result({
          connection_id: typeof grant === 'string' ? grant : null,
          admin_url: new URL('/passkeys/admin', passkeyOrigin(this.env)!).href,
          executed: false,
        });
      });
      this.server.registerTool('request_maintenance_command', {
        description: 'Request a passkey review of an exact Bash command on an enrolled host. Pass the Tailscale IPv4, a fresh job UUID, the literal command, and a short statement of why it is needed. The host must be paired for command execution. Keep secrets out of the command and statement because they are visible on the review page. If a standing approval applies, use passkey_test_status to check an in-progress job. ' + approvalInstructions,
        inputSchema: z.strictObject({ ...jobSchema, host: z.string(), command: z.string().max(4096),
          statement: z.string().trim().min(1).max(240).regex(/^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+$/u),
        }),
      }, async ({ job_id, host, command, statement }, extra) => {
        const grant = extra.requestInfo?.headers[grantHeader];
        return result(await approvalStore(this.env).requestCommand(job_id, host, command, statement,
          typeof grant === 'string' ? grant : undefined));
      });
      this.server.registerTool('request_service_restart', {
        description: 'Request one owner passkey approval to restart only openbot-maintenance-demo.service on the selected enrolled Linux host. ' + approvalInstructions,
        inputSchema: z.strictObject({ ...jobSchema, host: z.string() }),
      }, async ({ job_id, host }) => result(await approvalStore(this.env).start(job_id, true, host, true)));
      this.server.registerTool('maintenance_host_status', {
        description: 'Read the last completed SSH enrollment check, optionally for a specific enrolled host.',
        inputSchema: { host: z.string().optional() },
      }, async ({ host }) => result(await approvalStore(this.env).hostStatus(host)));
      this.server.registerTool('maintenance_hosts', {
        description: 'List enrolled host addresses for selecting an SSH enrollment check target.',
        inputSchema: {},
      }, async () => result(await approvalStore(this.env).listHosts()));
    }
    this.server.registerTool('start_timing_probe',{
      description:'Schedule a no-op reliability probe. Use a fresh random UUID and reuse it if the call times out. No command is run.',
      inputSchema:{probe_id,delay_seconds:z.number().int().min(5).max(300)},
    },async ({probe_id,delay_seconds})=>output(await this.env.PROBES.getByName(probe_id).start(delay_seconds)));
    this.server.registerTool('timing_probe_status',{
      description:'Read the previously requested no-op probe status from a fresh session. No command is run.',
      inputSchema:{probe_id},
    },async ({probe_id})=>output(await this.env.PROBES.getByName(probe_id).status()));
    this.server.registerTool('screen_maintenance_command', {
      description:'Dry run only. Parses Bash and may show a no-op review form. Never executes anything.',
      inputSchema:z.strictObject({command:z.string().max(4096)}),
    }, async ({command}, extra) => {
      const {decision,reason,syntax_facts}=await classify(command);
      const result={request_id:crypto.randomUUID(),decision,reason,client_response:'not_requested',approval_verified:false,execution_authorized:false,executed:false};
      const assessment = decision === 'review' ? assessCommand(this.env.AI, command, { screening_reason: reason, syntax_facts }) : null;
      if (decision==='review') {
        if (!this.server.server.getClientCapabilities()?.elicitation) {
          result.client_response='elicitation_unavailable';
        } else try {
          const escaped=JSON.stringify(command).replace(/[^\x20-\x7e]/g, ch => '\\u'+ch.charCodeAt(0).toString(16).padStart(4,'0'));
          const answer=await this.elicitInput({
            message:`DRY RUN — no command will run.\nRequest: ${result.request_id}\nReason: ${reason}\nSubmitted command (escaped): ${escaped}`,
            requestedSchema:{type:'object',properties:{confirm_dry_run:{type:'boolean',title:'Confirm this test review (no command will run)'}},required:['confirm_dry_run']},
          }, {relatedRequestId:extra.requestId});
          // The MCP client can simulate any form answer. Record it for the dry run only.
          result.client_response=answer.action==='accept'?(answer.content?.confirm_dry_run===true?'accepted_test':'not_confirmed'):answer.action==='decline'?'declined':answer.action==='cancel'?'dismissed':'unexpected_response';
        } catch { result.client_response='elicitation_unavailable'; }
      }
      const outcome = { ...result, syntax_facts, model_assessment: await assessment };
      return {structuredContent:outcome,content:[{type:'text',text:JSON.stringify(outcome)}]};
    });
  }
}

const transport=MaintenanceAgent.serve('/mcp');
export default {
  async fetch(request:Request, env:Env, ctx:ExecutionContext) {
    const token=env.MCP_BEARER_TOKEN;
    const path = new URL(request.url).pathname;
    if (path.startsWith('/passkeys/') || path === '/setup') {
      if (env.PASSKEY_SETUP_TOKEN && env.PASSKEY_SETUP_TOKEN === token) return new Response(null, { status: 503 });
      return passkeyRoute(request, env);
    }
    const oauth = await oauthRoute(request, env);
    if (oauth) return oauth;
    if (!token || token.length<32) return new Response('PoC token not configured',{status:503});
    const auth=request.headers.get('Authorization');
    if (!auth?.startsWith('Bearer ')) return oauthUnauthorized(env);
    const bearer = auth.slice(7);
    const oauthToken = path === '/mcp' && new URL(request.url).origin === passkeyOrigin(env)?.origin &&
      await authenticatedOAuthGrant(env, bearer);
    if (!oauthToken) {
      if (bearer.length !== token.length) return oauthUnauthorized(env);
      const enc=new TextEncoder();
      const key=await crypto.subtle.importKey('raw',enc.encode(token),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
      const challenge=enc.encode('maintenance-poc-access-v1');
      const clientKey=await crypto.subtle.importKey('raw',enc.encode(bearer),{name:'HMAC',hash:'SHA-256'},false,['sign']);
      if (!await crypto.subtle.verify('HMAC',key,await crypto.subtle.sign('HMAC',clientKey,challenge),challenge)) return oauthUnauthorized(env);
    }
    if (request.headers.has('Origin')) return new Response('Browser origin not allowed',{status:403});
    if (request.method === 'GET' && path === '/health/ssh-backend') {
      const status = await env.HOST_PROBE?.prepareEnrollment().catch(() => null);
      const state = status?.state === 'connected' || status?.state === 'unconfigured'
        ? status.state
        : 'unavailable';
      return Response.json({ state }, {
        status: state === 'unavailable' ? 503 : 200,
        headers: { 'Cache-Control': 'no-store' },
      });
    }
    const length=request.headers.get('Content-Length');
    if (request.body && (!length || !/^\d{1,10}$/.test(length) || Number(length)>32768)) return new Response('A bounded request body is required',{status:413});
    // Do not pass the ingress access secret into the session object.
    const headers=new Headers(request.headers);
    headers.delete('Authorization');
    headers.delete(grantHeader);
    if (typeof oauthToken === 'string') {
      headers.set(grantHeader, oauthToken);
      if (request.method === 'POST' && !request.headers.has('Mcp-Session-Id') && request.body) {
        const initial = InitializeRequestSchema.safeParse(await request.clone().json().catch(() => null));
        if (initial.success) {
          const info = initial.data.params.clientInfo;
          const name = [info.title, info.name].find(value => typeof value === 'string' &&
            value.trim().length > 0 && value.trim().length <= 80 && !/[\p{C}\p{Zl}\p{Zp}]/u.test(value))?.trim();
          if (name) {
            await approvalStore(env).recordMcpClientName(oauthToken, name)
              .catch(() => console.warn('Could not update the MCP client label.'));
          }
        }
      }
    }
    return transport.fetch(new Request(request,{headers}),env,ctx);
  },
};
