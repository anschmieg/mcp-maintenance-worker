import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
const url=new URL(process.env.TEST_MCP_URL??'http://127.0.0.1:8795/mcp');
const token=process.env.MCP_BEARER_TOKEN;
assert.ok(token);
const probe_id=randomUUID(), delay_seconds=Number(process.env.PROBE_SECONDS??5);
async function call(name,args) {
 const client=new Client({name:'timing-reconnect-smoke',version:'1'});
 try {
  await client.connect(new StreamableHTTPClientTransport(url,{requestInit:{headers:{Authorization:`Bearer ${token}`}}}),{timeout:8000});
  const r=await client.callTool({name,arguments:args},undefined,{timeout:8000});
  assert.ok(!r.isError,JSON.stringify(r));
  assert.equal(r.structuredContent.executed,false);
  return r.structuredContent.probe;
 } finally {await client.close();}
}
const start=Date.now();
const args={probe_id,delay_seconds};
const original=await call('start_timing_probe',args);
const startMs=Date.now()-start;
assert.ok(!original.completed_at);
assert.equal((await call('start_timing_probe',args)).due_at,original.due_at);
console.log(`PASS: scheduled ${delay_seconds}s probe in ${startMs}ms; replay preserved deadline; MCP sessions closed`);
await new Promise(r=>setTimeout(r,delay_seconds*1000));
for(let i=0;i<10;i++) {
 const state=await call('timing_probe_status',{probe_id});
 assert.equal(state.due_at,original.due_at);
 if(state.completed_at) {
  assert.ok(state.completed_at>=state.due_at);
  assert.equal((await call('start_timing_probe',args)).completed_at,state.completed_at);
  console.log(`PASS: fresh MCP sessions saw persisted completion and retry kept it (${state.completed_at-state.due_at}ms after due time)`);
  process.exit(0);
 }
 await new Promise(r=>setTimeout(r,1000));
}
throw new Error('Durable alarm did not complete in test window');
