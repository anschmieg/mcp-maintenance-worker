import assert from 'node:assert/strict';
import { assessScope, scopeUnavailable } from './src/assessment.ts';

const parser = { screening_reason: 'review required', syntax_facts: [] };
const assess = (command, overrides, context = parser) => assessScope({
  async run(model, input) {
    assert.equal(model, '@cf/cloudflare/clef-flash');
    assert.deepEqual(input.state, { command, ...context });
    assert.equal(input.questions.opaque.type, 'choice');
    return {
      answers: Object.fromEntries(Object.keys(input.questions).map(key => {
        const { choice = 'no', probability = 0.98 } = overrides[key] ?? {};
        const probabilities = Object.fromEntries(['yes', 'no', 'unknown'].map(
          option => [option, option === choice ? probability : (1 - probability) / 2],
        ));
        return [key, { choice, probabilities }];
      })),
    };
  },
}, command, context);

assert.equal(await assess('echo hello', { output: { choice: 'yes' } }), 'Produces output.');
assert.equal(await assess('./maintenance.sh', {
  opaque: { choice: 'yes' }, deletion: { choice: 'unknown' },
}), 'Some effects depend on code or context PaSTA cannot inspect.');
assert.equal(await assess('cat ./app.log', {
  output: { choice: 'yes' }, read: { choice: 'yes' }, systemData: { choice: 'yes' },
  credentials: { choice: 'no', probability: 0.4 },
}), 'Produces output. May read sensitive system or application data. Some effects could not be determined.');
assert.equal(await assessScope({ run: async () => ({ answers: {} }) }, 'echo hello', parser), scopeUnavailable);
assert.equal(await assessScope(undefined, 'echo hello', parser), scopeUnavailable);
const redirect = { ...parser, syntax_facts: ['redirection'] };
const redirectWarning = 'Shell redirection may read or write files or change where output goes.';
assert.equal(await assess('echo hello > result.txt', {}, redirect), redirectWarning);
assert.equal(await assessScope(undefined, 'echo hello > result.txt', redirect), redirectWarning + ' ' + scopeUnavailable);
console.log('PASS: Scope summarizes structured answers and surfaces uncertainty or missing assessment');
