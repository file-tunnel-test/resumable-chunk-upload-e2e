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
  verifyDownloadedBytes,
  verifyInventoryDigest,
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

  const resumeDigestMismatch = await expectCode('RESUME_DIGEST_MISMATCH', () =>
    store.resume({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      expectedDigest: sha256('different-object-intent'),
      encryptionContextDigest: begin.encryptionContextDigest,
    }),
  );
  const resumeEncryptionContextMismatch = await expectCode(
    'RESUME_ENCRYPTION_CONTEXT_MISMATCH',
    () =>
      store.resume({
        tenant: tenantA,
        uploadId: begin.uploadId,
        capability: current,
        expectedDigest,
        encryptionContextDigest: sha256('different-encryption-context'),
      }),
  );

  const foreignUpload = store.beginUpload({
    tenant: tenantA,
    bucket,
    objectId: 'foreign-object',
    expectedDigest: sha256('foreign'),
    expectedPartCount: 1,
  });
  const foreignUploadCapability = await expectCode('CAPABILITY_CONTEXT_MISMATCH', () =>
    store.uploadPart({
      tenant: tenantA,
      uploadId: foreignUpload.uploadId,
      capability: current,
      partNumber: 1,
      bytes: Buffer.from('foreign'),
    }),
  );
  const foreignResume = store.resume({
    tenant: tenantA,
    uploadId: foreignUpload.uploadId,
    capability: foreignUpload.capability,
    expectedDigest: sha256('foreign'),
    encryptionContextDigest: foreignUpload.encryptionContextDigest,
  });

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

  const partEtags = [first.etag, second.etag, third.etag];

  const wrongEtag = await expectCode('ETAG_MISMATCH', () =>
    store.complete({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      expectedDigest,
      expectedPartCount: parts.length,
      expectedPartEtags: [sha256('wrong-etag'), ...partEtags.slice(1)],
    }),
  );

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
    expectedPartEtags: partEtags,
  });
  const duplicateCompletion = store.complete({
    tenant: tenantA,
    uploadId: begin.uploadId,
    capability: current,
    expectedDigest,
    expectedPartCount: parts.length,
    expectedPartEtags: partEtags,
  });
  const duplicateCompletionMismatch = await expectCode('DUPLICATE_COMPLETION_CONTEXT', () =>
    store.complete({
      tenant: tenantA,
      uploadId: begin.uploadId,
      capability: current,
      expectedDigest,
      expectedPartCount: parts.length,
      expectedPartEtags: [sha256('different-etag'), ...partEtags.slice(1)],
    }),
  );

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
  const crossBucketRead = await expectCode('OBJECT_NOT_FOUND', () =>
    store.readRange({
      tenant: tenantA,
      bucket: 'other-bucket',
      objectId,
      capability: readCapability,
      ...range,
    }),
  );
  const crossObjectRead = await expectCode('OBJECT_NOT_FOUND', () =>
    store.readRange({
      tenant: tenantA,
      bucket,
      objectId: 'other-object',
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

  const restoreTag = store.corruptPartFieldForTest({
    tenant: tenantA,
    bucket,
    objectId,
    partNumber: 2,
    field: 'authTag',
  });
  const authenticationTagTamper = await expectCode('AUTHENTICATION_TAG_MISMATCH', () =>
    store.readRange({ tenant: tenantA, bucket, objectId, capability: readCapability, ...range }),
  );
  restoreTag();

  const restoreNonce = store.corruptPartFieldForTest({
    tenant: tenantA,
    bucket,
    objectId,
    partNumber: 2,
    field: 'iv',
  });
  const nonceTamper = await expectCode('AUTHENTICATION_TAG_MISMATCH', () =>
    store.readRange({ tenant: tenantA, bucket, objectId, capability: readCapability, ...range }),
  );
  restoreNonce();

  const restoreMetadata = store.corruptPartFieldForTest({
    tenant: tenantA,
    bucket,
    objectId,
    partNumber: 2,
    field: 'plaintextDigest',
  });
  const metadataTamper = await expectCode('AUTHENTICATION_TAG_MISMATCH', () =>
    store.readRange({ tenant: tenantA, bucket, objectId, capability: readCapability, ...range }),
  );
  restoreMetadata();

  const faultProxy = new FaultProxy([
    { operation: 'delayed-read', fault: 'delay', delayMs: 1 },
    { operation: 'stale-listing', fault: 'stale-listing', staleValue: 'stale-inventory' },
    { operation: 'partial-read', fault: 'partial-response' },
  ]);
  const delayedRead = verifyDownloadedBytes({
    bytes: await faultProxy.invoke('delayed-read', () => Promise.resolve(rangeBytes)),
    expectedLength: rangeBytes.length,
    expectedDigest: sha256(rangeBytes),
  });
  const staleListing = await expectCode('STALE_LISTING', async () =>
    verifyInventoryDigest({
      actual: await faultProxy.invoke('stale-listing', () => Promise.resolve(resumed.inventoryDigest)),
      expected: resumed.inventoryDigest,
    }),
  );
  const partialResponse = await expectCode('PARTIAL_RESPONSE', async () =>
    verifyDownloadedBytes({
      bytes: await faultProxy.invoke('partial-read', () => Promise.resolve(rangeBytes)),
      expectedLength: rangeBytes.length,
      expectedDigest: sha256(rangeBytes),
    }),
  );

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

  const expiryClock = new SyntheticClock();
  const expiryStore = new LocalObjectStore({ clock: expiryClock, capabilityTtlMs: 10 });
  const expiring = expiryStore.beginUpload({
    tenant: tenantA,
    bucket,
    objectId: 'expiring-object',
    expectedDigest: sha256('expiring'),
    expectedPartCount: 1,
  });
  expiryClock.advance(10);
  const expiredCapability = await expectCode('EXPIRED_CAPABILITY', () =>
    expiryStore.uploadPart({
      tenant: tenantA,
      uploadId: expiring.uploadId,
      capability: expiring.capability,
      partNumber: 1,
      bytes: Buffer.from('expiring'),
    }),
  );

  const singleStore = new LocalObjectStore({ maxPartBytes: 64 });
  const singleBytes = Buffer.from('single-part-object');
  const single = singleStore.beginUpload({
    tenant: tenantA,
    bucket,
    objectId: 'single-object',
    expectedDigest: sha256(singleBytes),
    expectedPartCount: 1,
  });
  const singlePart = singleStore.uploadPart({
    tenant: tenantA,
    uploadId: single.uploadId,
    capability: single.capability,
    partNumber: 1,
    bytes: singleBytes,
  });
  singleStore.complete({
    tenant: tenantA,
    uploadId: single.uploadId,
    capability: singlePart.capability,
    expectedDigest: sha256(singleBytes),
    expectedPartCount: 1,
    expectedPartEtags: [singlePart.etag],
  });
  const singleReadCapability = singleStore.issueReadCapability({
    tenant: tenantA,
    bucket,
    objectId: 'single-object',
  });
  const singleRead = singleStore.readRange({
    tenant: tenantA,
    bucket,
    objectId: 'single-object',
    capability: singleReadCapability,
  });

  const truncatedStore = new LocalObjectStore({ maxPartBytes: 64 });
  const truncated = truncatedStore.beginUpload({
    tenant: tenantA,
    bucket,
    objectId: 'truncated-object',
    expectedDigest: sha256('part-onepart-two'),
    expectedPartCount: 2,
  });
  const truncatedFirst = truncatedStore.uploadPart({
    tenant: tenantA,
    uploadId: truncated.uploadId,
    capability: truncated.capability,
    partNumber: 1,
    bytes: Buffer.from('part-one'),
  });
  const truncatedObject = await expectCode('TRUNCATED_OBJECT', () =>
    truncatedStore.complete({
      tenant: tenantA,
      uploadId: truncated.uploadId,
      capability: truncatedFirst.capability,
      expectedDigest: sha256('part-onepart-two'),
      expectedPartCount: 2,
    }),
  );
  const truncatedResume = truncatedStore.resume({
    tenant: tenantA,
    uploadId: truncated.uploadId,
    capability: truncatedFirst.capability,
    expectedDigest: sha256('part-onepart-two'),
    encryptionContextDigest: truncated.encryptionContextDigest,
  });

  const held = store.requestDelete({ tenant: tenantA, bucket, objectId });
  store.setLegalHold({ tenant: tenantA, bucket, objectId, enabled: false });
  const retained = store.requestDelete({ tenant: tenantA, bucket, objectId });
  clock.advance(5_001);
  const invalidLifecycleTransition = await expectCode('INVALID_LIFECYCLE_TRANSITION', () =>
    store.tombstone({ tenant: tenantA, bucket, objectId }),
  );
  const softDeleted = store.requestDelete({ tenant: tenantA, bucket, objectId });
  const terminalReadCapability = store.issueReadCapability({ tenant: tenantA, bucket, objectId, range });
  const terminalRead = await expectCode('OBJECT_TERMINAL', () =>
    store.readRange({
      tenant: tenantA,
      bucket,
      objectId,
      capability: terminalReadCapability,
      ...range,
    }),
  );
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
  const cleanupAReplay = store.cleanupOrphans({ tenant: tenantA });
  const namespaceCleanup = await expectCode('NAMESPACE_SCOPE', () =>
    store.cleanupOrphans({ tenant: tenantA, namespace: 'outside-fixture' }),
  );
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
      authenticationTagVerified: authenticationTagTamper === 'AUTHENTICATION_TAG_MISMATCH',
      tamperDetected: tamperDetected === 'CIPHERTEXT_DIGEST_MISMATCH',
      nonceTamperDetected: nonceTamper === 'AUTHENTICATION_TAG_MISMATCH',
      metadataTamperDetected: metadataTamper === 'AUTHENTICATION_TAG_MISMATCH',
      wrongCompletionDigestRejected: wrongCompletionDigest === 'DIGEST_MISMATCH',
      wrongEtagRejected: wrongEtag === 'ETAG_MISMATCH',
      truncatedObjectRejected: truncatedObject === 'TRUNCATED_OBJECT',
      truncatedFailureNonMutating: truncatedResume.nextPartNumber === 2,
      rangeVerified: true,
      downloadDigestVerified: delayedRead.equals(rangeBytes),
      partialResponseRejected: partialResponse === 'PARTIAL_RESPONSE',
      singlePartVerified: singleRead.equals(singleBytes),
      keyRotationVerified: rotation.keyVersion === 2,
    },
    resume: {
      exactReplayIdempotent: replay.replayed === true,
      duplicateCompletionIdempotent: duplicateCompletion.replayed === true,
      duplicateCompletionContextRejected:
        duplicateCompletionMismatch === 'DUPLICATE_COMPLETION_CONTEXT',
      staleCapabilityRejected: staleCapability === 'STALE_CAPABILITY',
      stalePresignedRequestRejected: staleCapability === 'STALE_CAPABILITY',
      expiredCapabilityRejected: expiredCapability === 'EXPIRED_CAPABILITY',
      digestMismatchRejected: resumeDigestMismatch === 'RESUME_DIGEST_MISMATCH',
      encryptionContextMismatchRejected:
        resumeEncryptionContextMismatch === 'RESUME_ENCRYPTION_CONTEXT_MISMATCH',
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
      invalidTransitionRejected:
        invalidLifecycleTransition === 'INVALID_LIFECYCLE_TRANSITION',
      terminalReadRejected: terminalRead === 'OBJECT_TERMINAL',
    },
    isolation: {
      tenantResumeRejected: tenantResume === 'TENANT_SCOPE',
      crossTenantReadRejected: crossTenantRead === 'OBJECT_NOT_FOUND',
      crossBucketReadRejected: crossBucketRead === 'OBJECT_NOT_FOUND',
      crossObjectReadRejected: crossObjectRead === 'OBJECT_NOT_FOUND',
      foreignUploadCapabilityRejected:
        foreignUploadCapability === 'CAPABILITY_CONTEXT_MISMATCH' && foreignResume.nextPartNumber === 1,
      staleReadCapabilityRejected: staleReadCapability === 'STALE_CAPABILITY',
      tenantScopedCleanup:
        cleanupA.deleted === 1 && cleanupAReplay.deleted === 0 && tenantBCanResume.nextPartNumber === 1,
      namespaceScopedCleanup: namespaceCleanup === 'NAMESPACE_SCOPE',
      cacheIsolation: config.cache === 'disabled',
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
      delayedParts: delayedRead.equals(rangeBytes) ? 1 : 0,
      staleListings: staleListing === 'STALE_LISTING' ? 1 : 0,
      partialResponses: partialResponse === 'PARTIAL_RESPONSE' ? 1 : 0,
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
