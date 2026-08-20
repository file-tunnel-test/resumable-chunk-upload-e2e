import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  timingSafeEqual,
} from 'node:crypto';

export const EVIDENCE_SCHEMA = 'file-tunnel-test/object-storage-evidence/v1';
export const POLICY_VERSION = 'den-3431/v1';

export class StoreError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'StoreError';
    this.code = code;
  }
}

export class SyntheticClock {
  constructor(nowMs = Date.UTC(2026, 7, 19, 12, 0, 0)) {
    this.value = nowMs;
  }
  now() {
    return this.value;
  }
  advance(ms) {
    if (!Number.isSafeInteger(ms) || ms < 0) throw new TypeError('advance must be non-negative');
    this.value += ms;
  }
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function rawSha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
  return createHash('sha256').update(bytes).digest();
}

function b64url(value) {
  return Buffer.from(value).toString('base64url');
}

function parseB64url(value) {
  try {
    return Buffer.from(value, 'base64url');
  } catch {
    throw new StoreError('INVALID_CAPABILITY');
  }
}

function ensureText(value, label) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,127}$/i.test(value)) {
    throw new StoreError('INVALID_IDENTIFIER', `${label} is invalid`);
  }
  return value;
}

function ensureDigest(value, label = 'digest') {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new StoreError('INVALID_DIGEST', `${label} must be sha256`);
  }
  return value;
}

function mapKey(tenant, bucket, objectId) {
  return `${tenant}\u0000${bucket}\u0000${objectId}`;
}

function partAad(upload, partNumber, plaintextDigest) {
  return Buffer.from(
    canonicalJson({
      tenant: upload.tenant,
      bucket: upload.bucket,
      objectId: upload.objectId,
      intentDigest: upload.intentDigest,
      encryptionContextDigest: upload.encryptionContextDigest,
      keyVersion: upload.keyVersion,
      partNumber,
      plaintextDigest,
    }),
  );
}

export class LocalObjectStore {
  constructor({
    clock = new SyntheticClock(),
    namespace = 'den-3431-fixture',
    maxPartBytes = 64 * 1024,
    maxParts = 128,
    capabilityTtlMs = 60_000,
  } = {}) {
    this.clock = clock;
    this.namespace = ensureText(namespace, 'namespace');
    this.maxPartBytes = maxPartBytes;
    this.maxParts = maxParts;
    this.capabilityTtlMs = capabilityTtlMs;
    this.masterKey = rawSha256('den-3431 synthetic master key; never exported');
    this.capabilityKey = rawSha256('den-3431 synthetic capability key; never exported');
    this.uploads = new Map();
    this.objects = new Map();
    this.tombstones = new Map();
    this.sequence = 0;
    this.peakWorkingSetBytes = 0;
  }

  configEvidence() {
    return {
      namespaceDigest: sha256(this.namespace),
      maxPartBytes: this.maxPartBytes,
      maxParts: this.maxParts,
      capabilityTtlMs: this.capabilityTtlMs,
      encryption: {
        clientSide: 'AES-256-GCM',
        serverSide: 'provider-managed-metadata-only',
        aadVersion: 1,
      },
    };
  }

  _keyFor(tenant, keyVersion) {
    return createHmac('sha256', this.masterKey)
      .update(`tenant=${tenant};keyVersion=${keyVersion}`)
      .digest();
  }

  _ivFor(upload, partNumber) {
    return createHmac('sha256', this._keyFor(upload.tenant, upload.keyVersion))
      .update(`${upload.intentDigest}:${partNumber}`)
      .digest()
      .subarray(0, 12);
  }

  _inventory(upload) {
    return [...upload.parts.values()]
      .sort((a, b) => a.partNumber - b.partNumber)
      .map(({ partNumber, plaintextDigest, ciphertextDigest, plaintextLength }) => ({
        partNumber,
        plaintextDigest,
        ciphertextDigest,
        plaintextLength,
      }));
  }

  _inventoryDigest(upload) {
    return sha256(canonicalJson(this._inventory(upload)));
  }

  _claims(upload, kind) {
    return {
      version: 1,
      kind,
      tenant: upload.tenant,
      bucket: upload.bucket,
      objectId: upload.objectId,
      uploadId: upload.uploadId,
      intentDigest: upload.intentDigest,
      encryptionContextDigest: upload.encryptionContextDigest,
      expectedDigest: upload.expectedDigest,
      inventoryVersion: upload.inventoryVersion,
      inventoryDigest: this._inventoryDigest(upload),
      expiresAtMs: this.clock.now() + this.capabilityTtlMs,
    };
  }

  _signClaims(claims) {
    const payload = Buffer.from(canonicalJson(claims));
    const signature = createHmac('sha256', this.capabilityKey).update(payload).digest();
    return `${b64url(payload)}.${b64url(signature)}`;
  }

  _issueUploadCapability(upload) {
    return this._signClaims(this._claims(upload, 'upload'));
  }

  _verifyUploadCapability(upload, tenant, capability, { allowCompletedReplay = false } = {}) {
    if (typeof capability !== 'string' || !capability.includes('.')) {
      throw new StoreError('INVALID_CAPABILITY');
    }
    const [payloadText, signatureText, extra] = capability.split('.');
    if (extra !== undefined || !payloadText || !signatureText) {
      throw new StoreError('INVALID_CAPABILITY');
    }
    const payload = parseB64url(payloadText);
    const supplied = parseB64url(signatureText);
    const expected = createHmac('sha256', this.capabilityKey).update(payload).digest();
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      throw new StoreError('INVALID_CAPABILITY');
    }
    let claims;
    try {
      claims = JSON.parse(payload.toString('utf8'));
    } catch {
      throw new StoreError('INVALID_CAPABILITY');
    }
    if (claims.kind !== 'upload' || claims.version !== 1) {
      throw new StoreError('INVALID_CAPABILITY');
    }
    if (claims.expiresAtMs < this.clock.now()) throw new StoreError('EXPIRED_CAPABILITY');
    if (claims.tenant !== tenant || upload.tenant !== tenant) throw new StoreError('TENANT_SCOPE');
    for (const key of ['bucket', 'objectId', 'uploadId', 'intentDigest', 'encryptionContextDigest', 'expectedDigest']) {
      if (claims[key] !== upload[key]) throw new StoreError('CAPABILITY_CONTEXT_MISMATCH');
    }
    if (upload.state === 'complete' && allowCompletedReplay) return claims;
    if (upload.state !== 'open') throw new StoreError('UPLOAD_TERMINAL');
    if (
      claims.inventoryVersion !== upload.inventoryVersion ||
      claims.inventoryDigest !== this._inventoryDigest(upload)
    ) {
      throw new StoreError('STALE_CAPABILITY');
    }
    return claims;
  }

  beginUpload({
    tenant,
    bucket,
    objectId,
    expectedDigest,
    expectedPartCount,
    keyVersion = 1,
    encryptionMode = 'client-side-aes-256-gcm',
    retentionUntilMs = this.clock.now(),
    legalHold = false,
    expiresAtMs = this.clock.now() + 120_000,
  }) {
    tenant = ensureText(tenant, 'tenant');
    bucket = ensureText(bucket, 'bucket');
    objectId = ensureText(objectId, 'objectId');
    ensureDigest(expectedDigest, 'expectedDigest');
    if (!Number.isSafeInteger(expectedPartCount) || expectedPartCount < 1 || expectedPartCount > this.maxParts) {
      throw new StoreError('INVALID_PART_COUNT');
    }
    if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new StoreError('INVALID_KEY_VERSION');
    if (!Number.isSafeInteger(retentionUntilMs) || !Number.isSafeInteger(expiresAtMs)) {
      throw new StoreError('INVALID_TIMESTAMP');
    }
    const encryptionContext = {
      mode: encryptionMode,
      algorithm: 'AES-256-GCM',
      keyVersion,
      aadVersion: 1,
    };
    const intent = {
      tenant,
      bucket,
      objectId,
      expectedDigest,
      expectedPartCount,
      encryptionContext,
      namespace: this.namespace,
    };
    const uploadId = createHash('sha256')
      .update(canonicalJson({ ...intent, sequence: ++this.sequence }))
      .digest('hex');
    const upload = {
      ...intent,
      uploadId,
      intentDigest: sha256(canonicalJson(intent)),
      encryptionContextDigest: sha256(canonicalJson(encryptionContext)),
      keyVersion,
      retentionUntilMs,
      legalHold: Boolean(legalHold),
      expiresAtMs,
      createdAtMs: this.clock.now(),
      inventoryVersion: 0,
      parts: new Map(),
      state: 'open',
      completionCapabilityDigest: null,
      completedDigest: null,
    };
    this.uploads.set(uploadId, upload);
    return {
      uploadId,
      capability: this._issueUploadCapability(upload),
      intentDigest: upload.intentDigest,
      encryptionContextDigest: upload.encryptionContextDigest,
    };
  }

  _upload(uploadId) {
    const upload = this.uploads.get(uploadId);
    if (!upload) throw new StoreError('UNKNOWN_UPLOAD');
    return upload;
  }

  resume({ tenant, uploadId, capability, expectedDigest, encryptionContextDigest }) {
    const upload = this._upload(uploadId);
    this._verifyUploadCapability(upload, tenant, capability);
    if (expectedDigest !== upload.expectedDigest) throw new StoreError('RESUME_DIGEST_MISMATCH');
    if (encryptionContextDigest !== upload.encryptionContextDigest) {
      throw new StoreError('RESUME_ENCRYPTION_CONTEXT_MISMATCH');
    }
    return {
      nextPartNumber: upload.parts.size + 1,
      inventoryDigest: this._inventoryDigest(upload),
      capability: this._issueUploadCapability(upload),
    };
  }

  uploadPart({ tenant, uploadId, capability, partNumber, bytes }) {
    const upload = this._upload(uploadId);
    this._verifyUploadCapability(upload, tenant, capability);
    if (!Number.isSafeInteger(partNumber) || partNumber < 1 || partNumber > upload.expectedPartCount) {
      throw new StoreError('INVALID_PART_NUMBER');
    }
    if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
    if (bytes.length < 1 || bytes.length > this.maxPartBytes) throw new StoreError('PART_SIZE_LIMIT');

    const existing = upload.parts.get(partNumber);
    const plaintextDigest = sha256(bytes);
    if (existing) {
      if (existing.plaintextDigest !== plaintextDigest || existing.plaintextLength !== bytes.length) {
        throw new StoreError('REPLAYED_PART_CONFLICT');
      }
      return {
        replayed: true,
        nextPartNumber: upload.parts.size + 1,
        inventoryDigest: this._inventoryDigest(upload),
        capability: this._issueUploadCapability(upload),
      };
    }
    const nextPartNumber = upload.parts.size + 1;
    if (partNumber !== nextPartNumber) throw new StoreError('REORDERED_PART');

    const key = this._keyFor(upload.tenant, upload.keyVersion);
    const iv = this._ivFor(upload, partNumber);
    const aad = partAad(upload, partNumber, plaintextDigest);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
    const authTag = cipher.getAuthTag();
    upload.parts.set(partNumber, {
      partNumber,
      ciphertext,
      ciphertextDigest: sha256(ciphertext),
      plaintextDigest,
      plaintextLength: bytes.length,
      iv,
      authTag,
      keyVersion: upload.keyVersion,
    });
    upload.inventoryVersion += 1;
    this.peakWorkingSetBytes = Math.max(this.peakWorkingSetBytes, bytes.length + ciphertext.length);
    return {
      replayed: false,
      nextPartNumber: upload.parts.size + 1,
      inventoryDigest: this._inventoryDigest(upload),
      capability: this._issueUploadCapability(upload),
    };
  }

  _decryptPart(container, part) {
    if (sha256(part.ciphertext) !== part.ciphertextDigest) throw new StoreError('CIPHERTEXT_DIGEST_MISMATCH');
    const key = this._keyFor(container.tenant, part.keyVersion);
    const aad = partAad(container, part.partNumber, part.plaintextDigest);
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, part.iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(part.authTag);
      const plaintext = Buffer.concat([decipher.update(part.ciphertext), decipher.final()]);
      if (plaintext.length !== part.plaintextLength || sha256(plaintext) !== part.plaintextDigest) {
        throw new StoreError('PLAINTEXT_DIGEST_MISMATCH');
      }
      this.peakWorkingSetBytes = Math.max(this.peakWorkingSetBytes, plaintext.length + part.ciphertext.length);
      return plaintext;
    } catch (error) {
      if (error instanceof StoreError) throw error;
      throw new StoreError('AUTHENTICATION_TAG_MISMATCH');
    }
  }

  complete({ tenant, uploadId, capability, expectedDigest, expectedPartCount }) {
    const upload = this._upload(uploadId);
    if (upload.state === 'complete') {
      this._verifyUploadCapability(upload, tenant, capability, { allowCompletedReplay: true });
      if (sha256(capability) !== upload.completionCapabilityDigest) throw new StoreError('DUPLICATE_COMPLETION_CONTEXT');
      if (expectedDigest !== upload.completedDigest || expectedPartCount !== upload.expectedPartCount) {
        throw new StoreError('DUPLICATE_COMPLETION_CONTEXT');
      }
      return { replayed: true, objectDigest: upload.completedDigest };
    }
    this._verifyUploadCapability(upload, tenant, capability);
    if (expectedDigest !== upload.expectedDigest) throw new StoreError('DIGEST_MISMATCH');
    if (expectedPartCount !== upload.expectedPartCount || upload.parts.size !== upload.expectedPartCount) {
      throw new StoreError('TRUNCATED_OBJECT');
    }
    const hash = createHash('sha256');
    let contentLength = 0;
    for (let number = 1; number <= upload.expectedPartCount; number += 1) {
      const part = upload.parts.get(number);
      if (!part) throw new StoreError('TRUNCATED_OBJECT');
      const plaintext = this._decryptPart(upload, part);
      hash.update(plaintext);
      contentLength += plaintext.length;
    }
    const computed = `sha256:${hash.digest('hex')}`;
    if (computed !== upload.expectedDigest) throw new StoreError('DIGEST_MISMATCH');
    const object = {
      tenant: upload.tenant,
      bucket: upload.bucket,
      objectId: upload.objectId,
      intentDigest: upload.intentDigest,
      expectedDigest: upload.expectedDigest,
      encryptionContextDigest: upload.encryptionContextDigest,
      keyVersion: upload.keyVersion,
      algorithm: 'AES-256-GCM',
      parts: new Map(upload.parts),
      partCount: upload.expectedPartCount,
      contentLength,
      state: 'active',
      stateVersion: 1,
      retentionUntilMs: upload.retentionUntilMs,
      legalHold: upload.legalHold,
      deletionStatus: 'unknown',
    };
    this.objects.set(mapKey(object.tenant, object.bucket, object.objectId), object);
    upload.state = 'complete';
    upload.completionCapabilityDigest = sha256(capability);
    upload.completedDigest = computed;
    return {
      replayed: false,
      objectDigest: computed,
      metadata: {
        algorithm: object.algorithm,
        keyVersion: object.keyVersion,
        encryptionContextDigest: object.encryptionContextDigest,
        partCount: object.partCount,
        contentLength: object.contentLength,
      },
    };
  }

  _object(tenant, bucket, objectId) {
    const object = this.objects.get(mapKey(tenant, bucket, objectId));
    if (!object) throw new StoreError('OBJECT_NOT_FOUND');
    return object;
  }

  issueReadCapability({ tenant, bucket, objectId, range = null }) {
    const object = this._object(tenant, bucket, objectId);
    if (object.tenant !== tenant) throw new StoreError('TENANT_SCOPE');
    const claims = {
      version: 1,
      kind: 'read',
      tenant,
      bucket,
      objectId,
      stateVersion: object.stateVersion,
      range,
      expiresAtMs: this.clock.now() + this.capabilityTtlMs,
    };
    return this._signClaims(claims);
  }

  _verifyReadCapability(object, tenant, capability, range) {
    if (typeof capability !== 'string') throw new StoreError('INVALID_CAPABILITY');
    const [payloadText, signatureText, extra] = capability.split('.');
    if (extra !== undefined || !payloadText || !signatureText) throw new StoreError('INVALID_CAPABILITY');
    const payload = parseB64url(payloadText);
    const supplied = parseB64url(signatureText);
    const expected = createHmac('sha256', this.capabilityKey).update(payload).digest();
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) {
      throw new StoreError('INVALID_CAPABILITY');
    }
    let claims;
    try { claims = JSON.parse(payload.toString('utf8')); } catch { throw new StoreError('INVALID_CAPABILITY'); }
    if (claims.kind !== 'read' || claims.version !== 1) throw new StoreError('INVALID_CAPABILITY');
    if (claims.expiresAtMs < this.clock.now()) throw new StoreError('EXPIRED_CAPABILITY');
    if (claims.tenant !== tenant || object.tenant !== tenant) throw new StoreError('TENANT_SCOPE');
    if (claims.bucket !== object.bucket || claims.objectId !== object.objectId) {
      throw new StoreError('CAPABILITY_CONTEXT_MISMATCH');
    }
    if (claims.stateVersion !== object.stateVersion) throw new StoreError('STALE_CAPABILITY');
    if (canonicalJson(claims.range) !== canonicalJson(range)) throw new StoreError('RANGE_SCOPE');
  }

  readRange({ tenant, bucket, objectId, capability, start = 0, endExclusive = null }) {
    const object = this._object(tenant, bucket, objectId);
    const end = endExclusive ?? object.contentLength;
    const range = { start, endExclusive: end };
    this._verifyReadCapability(object, tenant, capability, range);
    if (object.state !== 'active') throw new StoreError('OBJECT_TERMINAL');
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start || end > object.contentLength) {
      throw new StoreError('INVALID_RANGE');
    }
    let cursor = 0;
    const pieces = [];
    for (let number = 1; number <= object.partCount; number += 1) {
      const part = object.parts.get(number);
      const partStart = cursor;
      const partEnd = cursor + part.plaintextLength;
      cursor = partEnd;
      if (partEnd <= start || partStart >= end) continue;
      const plaintext = this._decryptPart(object, part);
      const localStart = Math.max(start, partStart) - partStart;
      const localEnd = Math.min(end, partEnd) - partStart;
      pieces.push(plaintext.subarray(localStart, localEnd));
    }
    const result = Buffer.concat(pieces);
    if (result.length !== end - start) throw new StoreError('PARTIAL_RESPONSE');
    return result;
  }

  corruptCiphertextForTest({ tenant, bucket, objectId, partNumber }) {
    const object = this._object(tenant, bucket, objectId);
    const part = object.parts.get(partNumber);
    if (!part) throw new StoreError('UNKNOWN_PART');
    const previous = Buffer.from(part.ciphertext);
    part.ciphertext[0] ^= 0x01;
    return () => { part.ciphertext = previous; };
  }

  rotateKey({ tenant, bucket, objectId, newKeyVersion }) {
    const object = this._object(tenant, bucket, objectId);
    if (object.state !== 'active') throw new StoreError('OBJECT_TERMINAL');
    if (!Number.isSafeInteger(newKeyVersion) || newKeyVersion <= object.keyVersion) {
      throw new StoreError('INVALID_KEY_VERSION');
    }
    const plaintextParts = [...object.parts.values()]
      .sort((a, b) => a.partNumber - b.partNumber)
      .map((part) => [part.partNumber, this._decryptPart(object, part)]);
    object.keyVersion = newKeyVersion;
    object.encryptionContextDigest = sha256(canonicalJson({
      mode: 'client-side-aes-256-gcm',
      algorithm: 'AES-256-GCM',
      keyVersion: newKeyVersion,
      aadVersion: 1,
    }));
    const next = new Map();
    for (const [partNumber, plaintext] of plaintextParts) {
      const plaintextDigest = sha256(plaintext);
      const key = this._keyFor(object.tenant, object.keyVersion);
      const iv = this._ivFor(object, partNumber);
      const aad = partAad(object, partNumber, plaintextDigest);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      next.set(partNumber, {
        partNumber,
        ciphertext,
        ciphertextDigest: sha256(ciphertext),
        plaintextDigest,
        plaintextLength: plaintext.length,
        iv,
        authTag: cipher.getAuthTag(),
        keyVersion: newKeyVersion,
      });
    }
    object.parts = next;
    object.stateVersion += 1;
    return {
      algorithm: object.algorithm,
      keyVersion: object.keyVersion,
      encryptionContextDigest: object.encryptionContextDigest,
    };
  }

  setLegalHold({ tenant, bucket, objectId, enabled }) {
    const object = this._object(tenant, bucket, objectId);
    object.legalHold = Boolean(enabled);
    object.stateVersion += 1;
  }

  requestDelete({ tenant, bucket, objectId }) {
    const object = this._object(tenant, bucket, objectId);
    if (object.legalHold) {
      object.deletionStatus = 'pending';
      return { state: object.state, deletionStatus: 'pending', reason: 'legal-hold' };
    }
    if (this.clock.now() < object.retentionUntilMs) {
      object.deletionStatus = 'pending';
      return { state: object.state, deletionStatus: 'pending', reason: 'retention' };
    }
    if (object.state === 'active') {
      object.state = 'soft-deleted';
      object.stateVersion += 1;
    }
    object.deletionStatus = 'requested';
    return { state: object.state, deletionStatus: 'requested' };
  }

  tombstone({ tenant, bucket, objectId }) {
    const object = this._object(tenant, bucket, objectId);
    if (object.legalHold || this.clock.now() < object.retentionUntilMs) throw new StoreError('RETENTION_BLOCK');
    if (object.state !== 'soft-deleted') throw new StoreError('INVALID_LIFECYCLE_TRANSITION');
    object.state = 'tombstoned';
    object.stateVersion += 1;
    object.deletionStatus = 'requested';
    return { state: object.state, deletionStatus: object.deletionStatus };
  }

  hardDelete({ tenant, bucket, objectId }) {
    const key = mapKey(tenant, bucket, objectId);
    const object = this._object(tenant, bucket, objectId);
    if (object.legalHold || this.clock.now() < object.retentionUntilMs) throw new StoreError('RETENTION_BLOCK');
    if (object.state !== 'tombstoned') throw new StoreError('INVALID_LIFECYCLE_TRANSITION');
    this.objects.delete(key);
    this.tombstones.set(key, {
      tenantDigest: sha256(tenant),
      bucketDigest: sha256(bucket),
      objectDigest: sha256(objectId),
      deletionStatus: 'verified',
      deletedAtMs: this.clock.now(),
    });
    return { deletionStatus: 'verified' };
  }

  deletionEvidence({ tenant, bucket, objectId }) {
    const key = mapKey(tenant, bucket, objectId);
    if (this.tombstones.has(key)) return this.tombstones.get(key).deletionStatus;
    const object = this.objects.get(key);
    return object?.deletionStatus ?? 'unknown';
  }

  cleanupOrphans({ tenant, namespace = this.namespace }) {
    if (namespace !== this.namespace) throw new StoreError('NAMESPACE_SCOPE');
    let deleted = 0;
    for (const [uploadId, upload] of this.uploads) {
      if (
        upload.tenant === tenant &&
        upload.namespace === namespace &&
        upload.state === 'open' &&
        upload.expiresAtMs <= this.clock.now()
      ) {
        this.uploads.delete(uploadId);
        deleted += 1;
      }
    }
    return { deleted, deletionStatus: 'verified' };
  }
}

export class FaultProxy {
  constructor(plan = []) {
    this.plan = [...plan];
    this.calls = 0;
  }

  async invoke(operation, action) {
    this.calls += 1;
    const next = this.plan.shift();
    if (next && next.operation === operation) {
      if (next.fault === 'disconnect') throw new StoreError('INJECTED_DISCONNECT');
      if (next.fault === 'delay') await new Promise((resolve) => setTimeout(resolve, next.delayMs ?? 1));
      const result = await action();
      if (next.fault === 'partial-response') {
        if (!Buffer.isBuffer(result) || result.length < 2) throw new StoreError('INVALID_FAULT_TARGET');
        return result.subarray(0, result.length - 1);
      }
      if (next.fault === 'stale-listing') return next.staleValue;
      return result;
    }
    return action();
  }
}

export function assertStoreError(error, code) {
  if (!(error instanceof StoreError) || error.code !== code) {
    throw new Error(`expected ${code}, received ${error?.code ?? error}`);
  }
}
