import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';

const endpoint = new URL(process.env.TEST_MCP_URL ?? 'http://127.0.0.1:8795/mcp');
const token = process.env.MCP_BEARER_TOKEN;
assert.ok(token && token.length >= 32);
assert.equal((await fetch(endpoint)).status, 401);
for (const [command, action, confirm, response, decision = 'review', expectedImpact, expectedFacts = []] of [
  ['uptime', 'accept', true, 'not_requested', 'auto_candidate'],
  ['uptime # diagnostic comment', 'decline', false, 'declined'],
  ['uptime;', 'decline', false, 'declined'],
  ["printf '%s' 'literal | pipe'", 'decline', false, 'declined'],
  ['printf "%s" "$(uptime | wc)"', 'decline', false, 'declined', 'review', undefined, ['command_substitution', 'pipeline']],
  ['printf hello > /tmp/maintenance-demo.txt', 'decline', false, 'declined', 'review', 'scratch_write', ['redirection']],
  ['cat /etc/shadow', 'decline', false, 'declined', 'review', 'sensitive_read'],
  ['systemctl restart maintenance-demo.service', 'decline', false, 'declined', 'review', 'consequential_change'],
  ['"$MAINTENANCE_ACTION"', 'decline', false, 'declined', 'review', 'uncertain', ['parameter_expansion']],
  ['uptime\u202e', 'accept', true, 'not_requested', 'invalid'],
  ['uptime | wc','accept',true,'accepted_test','review','diagnostic',['pipeline']],
  ['uptime | wc','accept',false,'not_confirmed','review',undefined,['pipeline']],
  ['uptime | wc','decline',false,'declined','review',undefined,['pipeline']],
  ['uptime | wc','cancel',false,'dismissed','review',undefined,['pipeline']],
  ['uptime | wc',null,false,'elicitation_unavailable','review',undefined,['pipeline']],
]) {
  const client = new Client({name:'maintenance-poc-smoke',version:'1'}, {capabilities:action ? {elicitation:{form:{}}} : {}});
  let prompt;
  if (action) client.setRequestHandler(ElicitRequestSchema, async ({params})=>{
    prompt=params.message;
    assert.ok(prompt.includes('DRY RUN'));
    return action==='accept' ? {action,content:{confirm_dry_run:confirm}} : {action};
  });
  const transport = new StreamableHTTPClientTransport(endpoint,{requestInit:{headers:{Authorization:`Bearer ${token}`}}});
  try {
    await client.connect(transport,{timeout:5000});
    assert.ok((await client.listTools()).tools.some(t=>t.name==='screen_maintenance_command'));
    const result=await client.callTool({name:'screen_maintenance_command',arguments:{command}},undefined,{timeout:7000});
    assert.ok(!result.isError,JSON.stringify(result));
    assert.equal(result.structuredContent?.executed,false);
    assert.equal(result.structuredContent?.approval_verified,false);
    assert.equal(result.structuredContent?.execution_authorized,false);
    assert.equal(result.structuredContent?.decision,decision);
    assert.deepEqual(result.structuredContent?.syntax_facts, expectedFacts);
    const assessment = result.structuredContent?.model_assessment;
    if (decision === 'review') {
      assert.equal(assessment?.model, '@cf/cloudflare/clef-flash');
      if (process.env.REQUIRE_MODEL_ASSESSMENT === '1') assert.equal(assessment.status, 'assessed');
      if (assessment.status === 'assessed') {
        assert.ok(['diagnostic', 'scratch_write', 'sensitive_read', 'consequential_change', 'uncertain'].includes(assessment.impact));
      } else {
        assert.equal(assessment.status, 'unavailable');
      }
    } else {
      assert.equal(assessment, null);
    }
    if (expectedImpact && process.env.REQUIRE_MODEL_ASSESSMENT === '1') {
      assert.equal(assessment.impact, expectedImpact, command);
    }
    assert.equal(result.structuredContent?.client_response,response);
    if (response==='not_requested' || response==='elicitation_unavailable') assert.equal(prompt,undefined);
    else assert.ok(prompt.includes(result.structuredContent.request_id));
    console.log(`PASS: ${response}${assessment ? ` (${assessment.impact ?? assessment.status})` : ''}`);
  } finally { await client.close(); }
}

const client = new Client({name:'maintenance-poc-input-contract',version:'1'});
try {
  await client.connect(new StreamableHTTPClientTransport(endpoint, {
    requestInit:{headers:{Authorization:`Bearer ${token}`}},
  }), {timeout:5000});
  const result = await client.callTool({
    name:'screen_maintenance_command',
    arguments:{command:'uptime', approval_verified:true},
  });
  assert.equal(result.isError, true);
  console.log('PASS: approval is not a tool argument');
} finally {
  await client.close();
}
