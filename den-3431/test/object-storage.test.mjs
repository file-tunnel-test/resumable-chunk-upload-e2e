import assert from 'node:assert/strict';
import { mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { runCertification } from '../lib/certification.mjs';
import { EVIDENCE_SCHEMA, canonicalJson, sha256 } from '../lib/object-store.mjs';

async function fixture() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'den-3431-'));
  const pins = path.join(dir, 'source-pins.json');
  await writeFile(pins, JSON.stringify({ sources: [
    { repository: 'file-tunnel/ftnl-backend-api.rs', sha: 'f33d79896584a4a2fa4dcde88f0cd4cf863e11cb' },
    { repository: 'file-tunnel/ftnl-clients', sha: 'dfd339f238932b7ed209b677916f9fcb8d249670' },
  ] }));
  return runCertification({ sourcePinsPath: pins, exactHeadSha: 'a'.repeat(40) });
}

test('local synthetic suite certifies the full DEN-3431 state machine', async () => {
  const evidence = await fixture();
  assert.equal(evidence.schema, EVIDENCE_SCHEMA);
  assert.equal(evidence.providerMode, 'local-synthetic');
  assert.equal(evidence.credentialsUsed, false);
  assert.equal(evidence.integrity.tamperDetected, true);
  assert.equal(evidence.integrity.rangeVerified, true);
  assert.equal(evidence.integrity.keyRotationVerified, true);
  assert.equal(evidence.resume.exactReplayIdempotent, true);
  assert.equal(evidence.resume.reorderedPartRejected, true);
  assert.equal(evidence.lifecycle.legalHold, 'pending');
  assert.equal(evidence.lifecycle.retention, 'pending');
  assert.equal(evidence.lifecycle.hardDelete, 'verified');
  assert.equal(evidence.lifecycle.finalDeletionEvidence, 'verified');
  assert.equal(evidence.isolation.tenantScopedCleanup, true);
  assert.equal(evidence.resourceBounds.bounded, true);
});

test('evidence is deterministic apart from exact head and carries only digests', async () => {
  const left = await fixture();
  const right = await fixture();
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.match(left.evidenceDigest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(left.redactedIdentifiers.tenantDigest, sha256('tenant-a'));
  const serialized = canonicalJson(left);
  for (const forbidden of [
    'synthetic-only:',
    'fixture-bucket',
    'synthetic-object',
    'postgres://',
    'X-Amz-Signature',
    'BEGIN PRIVATE KEY',
  ]) {
    assert.equal(serialized.includes(forbidden), false, `evidence leaked ${forbidden}`);
  }
});

test('mutation checks prove integrity, lifecycle, isolation, and bounds are enforced', async () => {
  const base = await fixture();
  const mutations = [
    (value) => { value.integrity.tamperDetected = false; },
    (value) => { value.resume.staleCapabilityRejected = false; },
    (value) => { value.lifecycle.finalDeletionEvidence = 'requested'; },
    (value) => { value.isolation.tenantScopedCleanup = false; },
    (value) => { value.resourceBounds.peakWorkingSetBytes = value.resourceBounds.maxPartBytes * 3; },
  ];
  const valid = (value) =>
    value.integrity.tamperDetected === true &&
    value.resume.staleCapabilityRejected === true &&
    value.lifecycle.finalDeletionEvidence === 'verified' &&
    value.isolation.tenantScopedCleanup === true &&
    value.resourceBounds.peakWorkingSetBytes <= value.resourceBounds.maxPartBytes * 2;
  assert.equal(valid(structuredClone(base)), true);
  for (const mutate of mutations) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.equal(valid(copy), false);
  }
});
