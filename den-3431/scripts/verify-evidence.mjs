import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { EVIDENCE_SCHEMA, canonicalJson, sha256 } from '../lib/object-store.mjs';

const path = process.argv[2];
if (!path) throw new Error('usage: verify-evidence.mjs PATH');
const raw = await readFile(path, 'utf8');
const evidence = JSON.parse(raw);
assert.equal(evidence.schema, EVIDENCE_SCHEMA);
assert.match(evidence.exactHeadSha, /^[0-9a-f]{40}$/);
assert.equal(evidence.providerMode, 'local-synthetic');
assert.equal(evidence.credentialsUsed, false);
assert.equal(evidence.rawIdentifiersRetained, false);
assert.equal(evidence.rawContentRetained, false);
assert.equal(evidence.integrity.tamperDetected, true);
assert.equal(evidence.integrity.authenticationTagVerified, true);
assert.equal(evidence.integrity.rangeVerified, true);
assert.equal(evidence.integrity.keyRotationVerified, true);
assert.equal(evidence.resume.exactReplayIdempotent, true);
assert.equal(evidence.resume.duplicateCompletionIdempotent, true);
assert.equal(evidence.resume.staleCapabilityRejected, true);
assert.equal(evidence.resume.reorderedPartRejected, true);
assert.equal(evidence.lifecycle.finalDeletionEvidence, 'verified');
assert.equal(evidence.isolation.tenantResumeRejected, true);
assert.equal(evidence.isolation.crossTenantReadRejected, true);
assert.equal(evidence.isolation.tenantScopedCleanup, true);
assert.equal(evidence.resourceBounds.bounded, true);
assert.ok(evidence.resourceBounds.peakWorkingSetBytes <= evidence.resourceBounds.maxPartBytes * 2);
const copy = structuredClone(evidence);
delete copy.evidenceDigest;
assert.equal(evidence.evidenceDigest, sha256(canonicalJson(copy)));
for (const forbidden of [
  'synthetic-only:',
  'fixture-bucket',
  'synthetic-object',
  'tenant-a',
  'tenant-b',
  'X-Amz-Signature',
  'Authorization: Bearer',
  'BEGIN PRIVATE KEY',
]) {
  assert.equal(raw.includes(forbidden), false, `evidence contains forbidden value ${forbidden}`);
}
console.log('DEN-3431 evidence verification: PASS');
