import { McpAgent } from 'agents/mcp';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import './wasm_exec.js';
import module from './screen.wasm';
import { assessCommand } from './assessment';
import { TimingProbe } from './timing';
import { approvalStore, passkeyOrigin, passkeyRoute, type PasskeyEnv } from './passkeys';
export { TimingProbe };
export { PasskeyApproval } from './passkeys';
type Env = PasskeyEnv & { MCP_BEARER_TOKEN?:string; PROBES: DurableObjectNamespace<TimingProbe>; AI?: Parameters<typeof assessCommand>[0] };

let ready: Promise<void> | undefined;
const g = globalThis as typeof globalThis & {
  Go: new () => { importObject: WebAssembly.Imports; run(wasm: WebAssembly.Instance): Promise<void> };
  maintenanceScreen?: (command: string) => { decision: string; reason: string; syntax_facts: string[] };
};
async function classify(command: string) {
  if (new TextEncoder().encode(command).length > 4096) return {decision:'invalid',reason:'command exceeds 4096 bytes',syntax_facts:[]};
  ready ??= (async () => {
    const go = new g.Go();
    const wasm = await WebAssembly.instantiate(module, go.importObject);
    void go.run(wasm).then(() => { g.maintenanceScreen = undefined; }).catch(() => { g.maintenanceScreen = undefined; });
    if (!g.maintenanceScreen) throw new Error('Wasm parser did not initialize');
  })();
  await ready;
  if (!g.maintenanceScreen) throw new Error('Wasm parser unavailable');
  return g.maintenanceScreen(command);
}

export class MaintenanceAgent extends McpAgent<Env> {
  server = new McpServer({name:'maintenance-screening-poc',version:'0.6.0'});
  async init() {
    const probe_id=z.string().uuid();
    const output=(probe:unknown)=>({content:[{type:'text' as const,text:JSON.stringify(probe)}],structuredContent:{probe,executed:false}});
    if (passkeyOrigin(this.env)) {
      const jobSchema = { job_id: z.string().uuid().toLowerCase() };
      const result = (job: Record<string, unknown>) => ({
        content: [{ type: 'text' as const, text: JSON.stringify(job) }], structuredContent: job,
      });
      this.server.registerTool('start_passkey_test', {
        description: 'Create a dry-run approval for a fixed enrollment diagnostic. Show the owner the review URL. No host action runs.',
        inputSchema: jobSchema,
      }, async ({ job_id }) => result(await approvalStore(this.env).start(job_id)));
      this.server.registerTool('passkey_test_status', {
        description: 'Read a passkey dry run or host enrollment check by its original job UUID.',
        inputSchema: jobSchema,
      }, async ({ job_id }) => result(await approvalStore(this.env).status(job_id)));
      this.server.registerTool('start_host_enrollment', {
        description: 'Request passkey approval to run the fixed openbot-enrollment-check-v1 SSH diagnostic. Show the owner the review URL.',
        inputSchema: jobSchema,
      }, async ({ job_id }) => result(await approvalStore(this.env).start(job_id, true)));
      this.server.registerTool('maintenance_host_status', {
        description: 'Read the last completed enrollment check for ams.',
        inputSchema: {},
      }, async () => result(await approvalStore(this.env).hostStatus()));
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
    if (new URL(request.url).pathname.startsWith('/passkeys/')) {
      if (env.PASSKEY_SETUP_TOKEN && env.PASSKEY_SETUP_TOKEN === token) return new Response(null, { status: 503 });
      return passkeyRoute(request, env);
    }
    if (!token || token.length<32) return new Response('PoC token not configured',{status:503});
    const auth=request.headers.get('Authorization');
    if (!auth || !auth.startsWith('Bearer ') || auth.length!==token.length+7) return new Response('Unauthorized',{status:401});
    const enc=new TextEncoder();
    const key=await crypto.subtle.importKey('raw',enc.encode(token),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
    const challenge=enc.encode('maintenance-poc-access-v1');
    const clientKey=await crypto.subtle.importKey('raw',enc.encode(auth.slice(7)),{name:'HMAC',hash:'SHA-256'},false,['sign']);
    if (!await crypto.subtle.verify('HMAC',key,await crypto.subtle.sign('HMAC',clientKey,challenge),challenge)) return new Response('Unauthorized',{status:401});
    if (request.headers.has('Origin')) return new Response('Browser origin not allowed',{status:403});
    const length=request.headers.get('Content-Length');
    if (request.body && (!length || !/^\d{1,10}$/.test(length) || Number(length)>32768)) return new Response('A bounded request body is required',{status:413});
    // Do not pass the ingress access secret into the session object.
    const headers=new Headers(request.headers);
    headers.delete('Authorization');
    return transport.fetch(new Request(request,{headers}),env,ctx);
  },
};
