// Read-only verification against the real server's parsers/signature validators.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const data = JSON.parse(readFileSync(0, 'utf8'));
const server = process.argv[2];
async function protocol(name) {
  const module = await import(pathToFileURL(join(server, 'src/runtime/protocol', name + '.ts')));
  return module.default ?? module;
}
const executor = await protocol('executor-proof');
const approval = await protocol('approval-claim');
const execution = await protocol('execution-receipt');
const observed = await protocol('observed-execution-receipt');
const key = { ...executor.parseExecutorPublicKey(data.publicKey),
  registeredAt: new Date(Date.now() - 60_000) };
const identity = { organisationId: data.organisationId, deploymentId: data.deploymentId,
  key, now: new Date() };
const kinds = new Set();
for (const record of data.records) {
  const body = record.body;
  let verify, parsed;
  if (record.path === '/evaluate') {
    assert(executor.validExecutorProof(body.identityProof));
    parsed = { ...record.executor, proof: body.identityProof };
    verify = executor.verifyExecutorProof;
    kinds.add('executor');
  } else if (record.path.startsWith('/approval-permits/')) {
    parsed = approval.parseApprovalClaim(body);
    verify = approval.verifyApprovalClaim;
    kinds.add('approval');
  } else if (record.path === '/execution-receipts') {
    parsed = execution.parseExecutionReceipt(body);
    verify = execution.verifyExecutionReceipt;
    assert.equal(execution.parseExecutionReceipt({ ...body, result: 'not permitted' }), null);
    kinds.add('execution');
  } else {
    assert.equal(record.path, '/execution/observed-receipts');
    parsed = observed.parseObservedExecutionReceipt(body);
    verify = observed.verifyObservedExecutionReceipt;
    assert.equal(observed.parseObservedExecutionReceipt({ ...body, permitId: data.deploymentId }), null);
    kinds.add('observed');
  }
  assert(parsed, record.path + ' rejected the Python shape');
  assert.equal(verify({ ...parsed, ...identity }), true, record.path + ' rejected the Python proof');
  assert.equal(verify({ ...parsed, ...identity, deploymentId: data.organisationId }), false);
  assert.equal(verify({ ...parsed, ...identity, inputSha256: 'f'.repeat(64) }), false);
}
assert.equal(kinds.size, 4);
console.log('AuthRail server protocol: all four Python proof kinds accepted; changed deployment/input rejected.');
