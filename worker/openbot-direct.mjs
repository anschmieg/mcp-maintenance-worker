// Direct OpenBot test adapter: forwards form elicitation over stdio, without rendering or answering it.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

const { MCP_BEARER_TOKEN: token, MCP_WORKER_URL } = process.env;
if (!token || !MCP_WORKER_URL) throw new Error('Set MCP_BEARER_TOKEN and MCP_WORKER_URL before starting the adapter');
const endpoint = new URL(MCP_WORKER_URL);
if (endpoint.protocol !== 'https:') throw new Error('The Worker URL must use HTTPS');
const server = new McpServer({ name: 'maintenance-direct-poc', version: '0.1.0' });
server.registerTool('screen_maintenance_command', {
  description: 'Dry run only. Ask the Cloudflare Worker to screen a command. A review sends native MCP elicitation; nothing executes.',
  inputSchema: { command: z.string().max(4096) },
}, async ({ command }, extra) => {
  const caps = server.server.getClientCapabilities()?.elicitation;
  const forms = !!caps && (caps.form !== undefined || Object.keys(caps).length === 0);
  const client = new Client({ name: 'openbot-direct-mcp-adapter', version: '0.1.0' }, { capabilities: forms ? { elicitation: { form: {} } } : {} });
  if (forms) client.setRequestHandler(ElicitRequestSchema, async ({ params }) => {
    if (params.mode === 'url') throw new Error('Only dry-run forms are supported');
    return await server.server.elicitInput({ ...params, mode: 'form' }, { relatedRequestId: extra.requestId, signal: extra.signal, timeout: 55000 });
  });
  try {
    await client.connect(new StreamableHTTPClientTransport(endpoint, { requestInit: { headers: { Authorization: `Bearer ${token}` } } }), { timeout: 8000, signal: extra.signal });
    const result = await client.callTool({ name: 'screen_maintenance_command', arguments: { command } }, undefined, { timeout: 65000, signal: extra.signal });
    const detail = `OpenBot client advertised form elicitation: ${forms ? 'yes' : 'no'}`;
    return { ...result, content: [...result.content, { type: 'text', text: detail }] };
  } finally { await client.close(); }
});
for (const [name, description, inputSchema = { job_id: z.string().uuid() }] of [
  ['start_passkey_test', 'Start a fixed dry-run approval. Present the returned review URL to the owner. No host action runs.'],
  ['passkey_test_status', 'Check a passkey dry run or host enrollment using its original job UUID.'],
  ['start_host_enrollment', 'Request passkey approval for the fixed SSH check on an enrolled host. Use the host address when more than one host is enrolled. Present the review URL to the owner.', { job_id: z.string().uuid(), host: z.string().optional() }],
  ['maintenance_host_status', 'Read the last completed SSH check, optionally for a specific enrolled host.', { host: z.string().optional() }],
  ['maintenance_hosts', 'List enrolled host addresses for selecting an SSH check target.', {}],
]) {
  server.registerTool(name, { description, inputSchema }, async (args, extra) => {
    const client = new Client({ name: 'openbot-direct-mcp-adapter', version: '0.1.0' });
    try {
      await client.connect(new StreamableHTTPClientTransport(endpoint, {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
      }), { timeout: 8000, signal: extra.signal });
      return await client.callTool({ name, arguments: args }, undefined, { timeout: 8000, signal: extra.signal });
    } finally { await client.close(); }
  });
}
await server.connect(new StdioServerTransport());
