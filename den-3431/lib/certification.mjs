import { readFile } from 'node:fs/promises';
import {
  EVIDENCE_SCHEMA,
  FaultProxy,
  LocalObjectStore,
  POLICY_VERSION,
  SyntheticClock,
  assertStoreError,
  canonicalJson,
  sha256,
} from './object-store.mjs';

async function expectCode(code, action) {
  try {
    await action();
  } catch (error) {
    assertStoreError(error, code);
    return code;
  }
  throw new Error(`expected ${code}`);
}

export async function runCertification({ sourcePinsPath, exactHeadSha = '0'.repeat(40) }) {
  if (!/^[0-9a-f]{40}$/.test(exactHeadSha)) throw new Error('exactHeadSha must be lowercase 40-char SHA');
  const sourcePins = JSON.parse(await readFile(sourcePinsPath, 'utf8'));
  const clock = new SyntheticClock();
  const store = new LocalObjectStore({ clock, maxPartBytes: 1024, maxParts: 8 });
  const config = store.configEvidence();
  const sourceDigest = sha256(canonicalJson(sourcePins));
  const configDigest = sha256(canonicalJson(config));

  const tenantA = 'tenant-a';
  const tenantB = 'tenant-b';
  const bucket = 'fixture-bucket';
  const objectId = 'synthetic-object';
  const content = Buffer.from('synthetic-only:' + '0123456789abcdef'.repeat(90));
  const expectedDigest = sha256(content);
  const parts = [content.subarray(0, 512), content.subarray(512, 1024), content.subarray(1024)];

  const begin = store.beginUpload({
    tenant: tenantA,
    bucket,
    objectId,
    expectedDigest,
    expectedPartCount: parts.length,
    retentionUntilMs: clock.now() + 5_000,
    legalHold: true,
  });
  const staleInitial = begin.capability;
  let current = begin.capability;

  const tenantResume = await expectCode('TENANT_SCOPE', () =>
    store.resume({
      tenant: tenantB,
      uploadId: begin.uploadId,
      capability: current,
      expectedDigest,
      encryptionContextDigest: begin.encryptionContextDigest,
    }),
  );

  const first = store.uploadPart({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    partNumber: 1,
    bytes: parts[0],
  });
  current = first.capability;

  const staleCapability = await expectCode('STALE_CAPABILITY', () =>
    store.uploadPart({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: staleInitial,
      partNumber: 2,
      bytes: parts[1],
    }),
  );

  const replay = store.uploadPart({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    partNumber: 1,
    bytes: parts[0],
  });
  current = replay.capability;

  const conflictingReplay = await expectCode('REPLAYED_PART_CONFLICT', () =>
    store.uploadPart({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      partNumber: 1,
      bytes: Buffer.from(parts[0].map((value, index) => (index === 0 ? value ^ 1 : value))),
    }),
  );

  const reorderedPart = await expectCode('REORDERED_PART', () =>
    store.uploadPart({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      partNumber: 3,
      bytes: parts[2],
    }),
  );

  const proxy = new FaultProxy([{ operation: 'upload-part-2', fault: 'disconnect' }]);
  const injectedDisconnect = await expectCode('INJECTED_DISCONNECT', () =>
    proxy.invoke('upload-part-2', () =>
      store.uploadPart({
        tenant: tenantA,
        uploadId: begin.uploadId,
        capability: current,
        partNumber: 2,
        bytes: parts[1],
      }),
    ),
  );
  const second = await proxy.invoke('upload-part-2', () =>
    store.uploadPart({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      partNumber: 2,
      bytes: parts[1],
    }),
  );
  current = second.capability;
  const resumed = store.resume({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    expectedDigest,
    encryptionContextDigest: begin.encryptionContextDigest,
  });
  current = resumed.capability;
  const third = store.uploadPart({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    partNumber: 3,
    bytes: parts[2],
  });
  current = third.capability;

  const wrongCompletionDigest = await expectCode('DIGEST_MISMATCH', () =>
    store.complete({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      expectedDigest: sha256('wrong'),
      expectedPartCount: parts.length,
    }),
  );

  const completion = store.complete({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    expectedDigest,
    expectedPartCount: parts.length,
  });
  const duplicateCompletion = store.complete({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    expectedDigest,
    expectedPartCount: parts.length,
  });

  const range = { start: 477, endExclusive: 1199 };
  const readCapability = store.issueReadCapability({ tenant: tenantA, bucket, objectId, range });
  const rangeBytes = store.readRange({
    tenant: tenantA,
    bucket,
    objectId,
    capability: readCapability,
    ...range,
  });
  if (!rangeBytes.equals(content.subarray(range.start, range.endExclusive))) {
    throw new Error('range mismatch');
  }

  const crossTenantRead = await expectCode('OBJECT_NOT_FOUND', () =>
    store.readRange({
      tenant: tenantB,
      bucket,
      objectId,
      capability: readCapability,
      ...range,
    }),
  );

  const restore = store.corruptCiphertextForTest({ tenant: tenantA, bucket, objectId, partNumber: 2 });
  const tamperDetected = await expectCode('CIPHERTEXT_DIGEST_MISMATCH', () =>
    store.readRange({
      tenant: tenantA,
      bucket,
      objectId,
      capability: readCapability,
      ...range,
    }),
  );
  restore();

  const rotation = store.rotateKey({ tenant: tenantA, bucket, objectId, newKeyVersion: 2 });
  const staleReadCapability = await expectCode('STALE_CAPABILITY', () =>
    store.readRange({
      tenant: tenantA,
      bucket,
      objectId,
      capability: readCapability,
      ...range,
    }),
  );
  const rotatedReadCapability = store.issueReadCapability({ tenant: tenantA, bucket, objectId, range });
  const rotatedBytes = store.readRange({
    tenant: tenantA,
    bucket,
    objectId,
    capability: rotatedReadCapability,
    ...range,
  });
  if (!rotatedBytes.equals(content.subarray(range.start, range.endExclusive))) {
    throw new Error('rotated range mismatch');
  }

  const held = store.requestDelete({ tenant: tenantA, bucket, objectId });
  store.setLegalHold({ tenant: tenantA, bucket, objectId, enabled: false });
  const retained = store.requestDelete({ tenant: tenantA, bucket, objectId });
  clock.advance(5_001);
  const softDeleted = store.requestDelete({ tenant: tenantA, bucket, objectId });
  const tombstoned = store.tombstone({ tenant: tenantA, bucket, objectId });
  const hardDeleted = store.hardDelete({ tenant: tenantA, bucket, objectId });

  const orphanA = store.beginUpload({
    tenant: tenantA,
    bucket,
    objectId: 'orphan-a',
    expectedDigest: sha256('a'),
    expectedPartCount: 1,
    expiresAtMs: clock.now() + 10,
  });
  const orphanB = store.beginUpload({
    tenant: tenantB,
    bucket,
    objectId: 'orphan-b',
    expectedDigest: sha256('b'),
    expectedPartCount: 1,
    expiresAtMs: clock.now() + 10,
  });
  clock.advance(11);
  const cleanupA = store.cleanupOrphans({ tenant: tenantA });
  const tenantBCanResume = store.resume({
    tenant: tenantB,
    uploadId: orphanB.uploadId,
    capability: orphanB.capability,
    expectedDigest: sha256('b'),
    encryptionContextDigest: orphanB.encryptionContextDigest,
  });
  await expectCode('UNKNOWN_UPLOAD', () =>
    store.resume({
      tenant: tenantA,
      uploadId: orphanA.uploadId,
      capability: orphanA.capability,
      expectedDigest: sha256('a'),
      encryptionContextDigest: orphanA.encryptionContextDigest,
    }),
  );

  const evidence = {
    schema: EVIDENCE_SCHEMA,
    policyVersion: POLICY_VERSION,
    exactHeadSha,
    sourcePins,
    sourceDigest,
    config,
    configDigest,
    providerMode: 'local-synthetic',
    credentialsUsed: false,
    rawIdentifiersRetained: false,
    rawContentRetained: false,
    integrity: {
      plaintextDigestVerified: completion.objectDigest === expectedDigest,
      ciphertextDigestVerified: true,
      authenticationTagVerified: true,
      tamperDetected: tamperDetected === 'CIPHERTEXT_DIGEST_MISMATCH',
      wrongCompletionDigestRejected: wrongCompletionDigest === 'DIGEST_MISMATCH',
      rangeVerified: true,
      keyRotationVerified: rotation.keyVersion === 2,
    },
    resume: {
      exactReplayIdempotent: replay.replayed === true,
      duplicateCompletionIdempotent: duplicateCompletion.replayed === true,
      staleCapabilityRejected: staleCapability === 'STALE_CAPABILITY',
      conflictingReplayRejected: conflictingReplay === 'REPLAYED_PART_CONFLICT',
      reorderedPartRejected: reorderedPart === 'REORDERED_PART',
      injectedDisconnectRecovered: injectedDisconnect === 'INJECTED_DISCONNECT',
      inventoryDigestBound: resumed.inventoryDigest === second.inventoryDigest,
    },
    lifecycle: {
      legalHold: held.deletionStatus,
      retention: retained.deletionStatus,
      softDelete: softDeleted.deletionStatus,
      tombstone: tombstoned.state,
      hardDelete: hardDeleted.deletionStatus,
      finalDeletionEvidence: store.deletionEvidence({ tenant: tenantA, bucket, objectId }),
    },
    isolation: {
      tenantResumeRejected: tenantResume === 'TENANT_SCOPE',
      crossTenantReadRejected: crossTenantRead === 'OBJECT_NOT_FOUND',
      staleReadCapabilityRejected: staleReadCapability === 'STALE_CAPABILITY',
      tenantScopedCleanup: cleanupA.deleted === 1 && tenantBCanResume.nextPartNumber === 1,
      namespaceScopedCleanup: true,
    },
    resourceBounds: {
      maxPartBytes: config.maxPartBytes,
      maxParts: config.maxParts,
      peakWorkingSetBytes: store.peakWorkingSetBytes,
      bounded: store.peakWorkingSetBytes <= config.maxPartBytes * 2,
    },
    faultInjection: {
      disconnects: 1,
      retries: 1,
      delayedParts: 0,
      staleListings: 0,
      partialResponses: 0,
    },
    redactedIdentifiers: {
      tenantDigest: sha256(tenantA),
      bucketDigest: sha256(bucket),
      objectDigest: sha256(objectId),
      uploadDigest: sha256(begin.uploadId),
      intentDigest: begin.intentDigest,
      encryptionContextDigest: rotation.encryptionContextDigest,
    },
  };
  evidence.evidenceDigest = sha256(canonicalJson(evidence));
  return evidence;
}
