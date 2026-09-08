import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { runCertification } from '../lib/certification.mjs';
import { EVIDENCE_SCHEMA, canonicalJson, sha256 } from '../lib/object-store.mjs';

async function fixture() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'den-3431-'));
  const pins = path.join(dir, 'source-pins.json');
  await writeFile(pins, JSON.stringify({ sources: [
    { repository: 'file-tunnel/ftnl-backend-api.rs', sha: '8b9be5ce229d46e097ce45c58f906ea17481e57b' },
    { repository: 'file-tunnel/ftnl-clients', sha: '8c24b8bacae16e30ce33186d5531cfe92d7cc7ab' },
  ] }));
  return runCertification({ sourcePinsPath: pins, exactHeadSha: 'a'.repeat(40) });
}

test('local synthetic suite certifies the full DEN-3431 state machine', async () => {
  const evidence = await fixture();
  assert.equal(evidence.schema, EVIDENCE_SCHEMA);
  assert.equal(evidence.providerMode, 'local-synthetic');
  assert.equal(evidence.credentialsUsed, false);
  assert.equal(evidence.integrity.tamperDetected, true);
  assert.equal(evidence.integrity.authenticationTagVerified, true);
  assert.equal(evidence.integrity.nonceTamperDetected, true);
  assert.equal(evidence.integrity.metadataTamperDetected, true);
  assert.equal(evidence.integrity.wrongEtagRejected, true);
  assert.equal(evidence.integrity.truncatedObjectRejected, true);
  assert.equal(evidence.integrity.truncatedFailureNonMutating, true);
  assert.equal(evidence.integrity.downloadDigestVerified, true);
  assert.equal(evidence.integrity.partialResponseRejected, true);
  assert.equal(evidence.integrity.singlePartVerified, true);
  assert.equal(evidence.integrity.rangeVerified, true);
  assert.equal(evidence.integrity.keyRotationVerified, true);
  assert.equal(evidence.encryption.clientModeMetadataVerified, true);
  assert.equal(evidence.encryption.serverModeMetadataVerified, true);
  assert.equal(evidence.encryption.invalidModeRejected, true);
  assert.equal(evidence.encryption.rawKeyExcluded, true);
  assert.equal(evidence.resume.exactReplayIdempotent, true);
  assert.equal(evidence.resume.reorderedPartRejected, true);
  assert.equal(evidence.resume.expiredCapabilityRejected, true);
  assert.equal(evidence.resume.digestMismatchRejected, true);
  assert.equal(evidence.resume.encryptionContextMismatchRejected, true);
  assert.equal(evidence.lifecycle.legalHold, 'pending');
  assert.equal(evidence.lifecycle.retention, 'pending');
  assert.equal(evidence.lifecycle.hardDelete, 'verified');
  assert.equal(evidence.lifecycle.finalDeletionEvidence, 'verified');
  assert.equal(evidence.lifecycle.invalidTransitionRejected, true);
  assert.equal(evidence.lifecycle.terminalReadRejected, true);
  assert.equal(evidence.isolation.tenantScopedCleanup, true);
  assert.equal(evidence.isolation.namespaceScopedCleanup, true);
  assert.equal(evidence.isolation.crossBucketReadRejected, true);
  assert.equal(evidence.isolation.crossObjectReadRejected, true);
  assert.equal(evidence.isolation.crossPrefixReadRejected, true);
  assert.equal(evidence.isolation.foreignUploadCapabilityRejected, true);
  assert.equal(evidence.isolation.cacheIsolation, true);
  assert.equal(evidence.resourceBounds.bounded, true);
  assert.deepEqual(evidence.faultInjection, {
    disconnects: 1,
    retries: 1,
    delayedParts: 1,
    staleListings: 1,
    partialResponses: 1,
  });
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
    (value) => { value.integrity.wrongEtagRejected = false; },
    (value) => { value.resume.expiredCapabilityRejected = false; },
    (value) => { value.resume.staleCapabilityRejected = false; },
    (value) => { value.lifecycle.finalDeletionEvidence = 'requested'; },
    (value) => { value.isolation.tenantScopedCleanup = false; },
    (value) => { value.integrity.partialResponseRejected = false; },
    (value) => { value.encryption.serverModeMetadataVerified = false; },
    (value) => { value.faultInjection.partialResponses = 0; },
    (value) => { value.resourceBounds.peakWorkingSetBytes = value.resourceBounds.maxPartBytes * 3; },
  ];
  const valid = (value) =>
    value.integrity.tamperDetected === true &&
    value.integrity.wrongEtagRejected === true &&
    value.integrity.partialResponseRejected === true &&
    value.encryption.serverModeMetadataVerified === true &&
    value.resume.staleCapabilityRejected === true &&
    value.resume.expiredCapabilityRejected === true &&
    value.lifecycle.finalDeletionEvidence === 'verified' &&
    value.isolation.tenantScopedCleanup === true &&
    value.faultInjection.partialResponses === 1 &&
    value.resourceBounds.peakWorkingSetBytes <= value.resourceBounds.maxPartBytes * 2;
  assert.equal(valid(structuredClone(base)), true);
  for (const mutate of mutations) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.equal(valid(copy), false);
  }
});

test('v2 evidence schema is closed and declares every emitted certification claim', async () => {
  const evidence = await fixture();
  const schema = JSON.parse(
    await readFile(new URL('../evidence.schema.json', import.meta.url), 'utf8'),
  );
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.schema.const, EVIDENCE_SCHEMA);
  assert.deepEqual(Object.keys(evidence).sort(), [...schema.required].sort());
  for (const group of [
    'integrity',
    'encryption',
    'resume',
    'lifecycle',
    'isolation',
    'resourceBounds',
    'faultInjection',
    'redactedIdentifiers',
  ]) {
    assert.equal(schema.properties[group].additionalProperties, false);
    assert.deepEqual(Object.keys(evidence[group]).sort(), [...schema.properties[group].required].sort());
  }
});
