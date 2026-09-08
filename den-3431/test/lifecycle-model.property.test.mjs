import assert from 'node:assert/strict';
import test from 'node:test';

import { LocalObjectStore, StoreError, sha256 } from '../lib/object-store.mjs';

function nextRandom(state) {
  return (Math.imul(state, 1664525) + 1013904223) >>> 0;
}

function expectCode(code, action) {
  assert.throws(action, (error) => error instanceof StoreError && error.code === code);
}

function completedObject(store, objectId) {
  const bytes = Buffer.from(`model-${objectId}`);
  const begin = store.beginUpload({
    tenant: 'model-tenant',
    bucket: 'model-bucket',
    objectId,
    expectedDigest: sha256(bytes),
    expectedPartCount: 1,
  });
  const part = store.uploadPart({
    tenant: 'model-tenant',
    uploadId: begin.uploadId,
    capability: begin.capability,
    partNumber: 1,
    bytes,
  });
  store.complete({
    tenant: 'model-tenant',
    uploadId: begin.uploadId,
    capability: part.capability,
    expectedDigest: sha256(bytes),
    expectedPartCount: 1,
    expectedPartEtags: [part.etag],
  });
  return bytes;
}

test('model-based lifecycle traces reject invalid transitions without state mutation', () => {
  const actions = ['request-delete', 'tombstone', 'hard-delete', 'read'];
  for (let trace = 0; trace < 64; trace += 1) {
    const store = new LocalObjectStore({ maxPartBytes: 64 });
    const objectId = `model-object-${trace}`;
    const bytes = completedObject(store, objectId);
    let model = 'active';
    let random = trace + 1;

    for (let step = 0; step < 24; step += 1) {
      random = nextRandom(random);
      const action = actions[random % actions.length];
      const beforeEvidence = store.deletionEvidence({
        tenant: 'model-tenant',
        bucket: 'model-bucket',
        objectId,
      });

      if (action === 'request-delete') {
        if (model === 'deleted') {
          expectCode('OBJECT_NOT_FOUND', () =>
            store.requestDelete({ tenant: 'model-tenant', bucket: 'model-bucket', objectId }),
          );
        } else {
          const result = store.requestDelete({
            tenant: 'model-tenant',
            bucket: 'model-bucket',
            objectId,
          });
          if (model === 'active') model = 'soft-deleted';
          assert.equal(result.state, model);
          assert.equal(result.deletionStatus, 'requested');
        }
      } else if (action === 'tombstone') {
        if (model === 'soft-deleted') {
          const result = store.tombstone({
            tenant: 'model-tenant',
            bucket: 'model-bucket',
            objectId,
          });
          model = 'tombstoned';
          assert.equal(result.state, model);
        } else {
          const code = model === 'deleted' ? 'OBJECT_NOT_FOUND' : 'INVALID_LIFECYCLE_TRANSITION';
          expectCode(code, () =>
            store.tombstone({ tenant: 'model-tenant', bucket: 'model-bucket', objectId }),
          );
        }
      } else if (action === 'hard-delete') {
        if (model === 'tombstoned') {
          assert.deepEqual(
            store.hardDelete({ tenant: 'model-tenant', bucket: 'model-bucket', objectId }),
            { deletionStatus: 'verified' },
          );
          model = 'deleted';
        } else {
          const code = model === 'deleted' ? 'OBJECT_NOT_FOUND' : 'INVALID_LIFECYCLE_TRANSITION';
          expectCode(code, () =>
            store.hardDelete({ tenant: 'model-tenant', bucket: 'model-bucket', objectId }),
          );
        }
      } else if (model === 'deleted') {
        expectCode('OBJECT_NOT_FOUND', () =>
          store.issueReadCapability({ tenant: 'model-tenant', bucket: 'model-bucket', objectId }),
        );
      } else {
        const capability = store.issueReadCapability({
          tenant: 'model-tenant',
          bucket: 'model-bucket',
          objectId,
        });
        if (model === 'active') {
          assert.deepEqual(
            store.readRange({
              tenant: 'model-tenant',
              bucket: 'model-bucket',
              objectId,
              capability,
            }),
            bytes,
          );
        } else {
          expectCode('OBJECT_TERMINAL', () =>
            store.readRange({
              tenant: 'model-tenant',
              bucket: 'model-bucket',
              objectId,
              capability,
            }),
          );
        }
      }

      const afterEvidence = store.deletionEvidence({
        tenant: 'model-tenant',
        bucket: 'model-bucket',
        objectId,
      });
      const expectedEvidence = model === 'deleted'
        ? 'verified'
        : model === 'active'
          ? 'unknown'
          : 'requested';
      assert.equal(afterEvidence, expectedEvidence);
      if (beforeEvidence === afterEvidence && model !== 'deleted') {
        assert.notEqual(afterEvidence, 'verified');
      }
    }
  }
});
