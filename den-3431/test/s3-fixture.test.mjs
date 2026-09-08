import assert from 'node:assert/strict';
import test from 'node:test';

import { startS3Fixture } from '../lib/s3-fixture.mjs';
import { LocalObjectStore, SyntheticClock, sha256 } from '../lib/object-store.mjs';

test('loopback S3-style multipart facade preserves capability, range, and tenant boundaries', async (t) => {
  const clock = new SyntheticClock();
  const store = new LocalObjectStore({ clock, maxPartBytes: 64 });
  const fixture = await startS3Fixture({ store });
  t.after(fixture.close);
  const tenant = 'tenant-http';
  const bucket = 'bucket-http';
  const objectId = 'prefix-a/object-http';
  const bytes = Buffer.from('0123456789abcdef'.repeat(6));
  const chunks = [bytes.subarray(0, 32), bytes.subarray(32, 64), bytes.subarray(64)];
  const expectedDigest = sha256(bytes);
  const objectUrl = `${fixture.origin}/${bucket}/${objectId}`;

  const beginResponse = await fetch(`${objectUrl}?uploads`, {
    method: 'POST',
    headers: {
      'x-ftnl-tenant': tenant,
      'x-ftnl-expected-sha256': expectedDigest,
      'x-ftnl-part-count': String(chunks.length),
    },
  });
  assert.equal(beginResponse.status, 200);
  const begin = await beginResponse.json();
  let capability = begin.capability;
  const partEtags = [];

  for (let index = 0; index < chunks.length; index += 1) {
    const response = await fetch(`${objectUrl}?partNumber=${index + 1}&uploadId=${begin.uploadId}`, {
      method: 'PUT',
      headers: { 'x-ftnl-tenant': tenant, 'x-ftnl-capability': capability },
      body: chunks[index],
    });
    assert.equal(response.status, 200);
    capability = response.headers.get('x-ftnl-next-capability');
    assert.ok(capability);
    const etag = response.headers.get('etag');
    assert.match(etag ?? '', /^"sha256:[0-9a-f]{64}"$/);
    partEtags.push(etag.slice(1, -1));
  }

  const wrongEtagResponse = await fetch(`${objectUrl}?uploadId=${begin.uploadId}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': capability,
    },
    body: JSON.stringify({
      expectedDigest,
      expectedPartCount: chunks.length,
      expectedPartEtags: [sha256('wrong-etag'), ...partEtags.slice(1)],
    }),
  });
  assert.equal(wrongEtagResponse.status, 409);
  assert.deepEqual(await wrongEtagResponse.json(), { error: 'ETAG_MISMATCH' });

  const completeResponse = await fetch(`${objectUrl}?uploadId=${begin.uploadId}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': capability,
    },
    body: JSON.stringify({
      expectedDigest,
      expectedPartCount: chunks.length,
      expectedPartEtags: partEtags,
    }),
  });
  assert.equal(completeResponse.status, 200);

  const range = { start: 17, endExclusive: 73 };
  const readCapability = store.issueReadCapability({ tenant, bucket, objectId, range });
  const rangeResponse = await fetch(objectUrl, {
    headers: {
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': readCapability,
      range: `bytes=${range.start}-${range.endExclusive - 1}`,
    },
  });
  assert.equal(rangeResponse.status, 206);
  assert.deepEqual(Buffer.from(await rangeResponse.arrayBuffer()), bytes.subarray(range.start, range.endExclusive));

  const crossTenant = await fetch(objectUrl, {
    headers: {
      'x-ftnl-tenant': 'tenant-other',
      'x-ftnl-capability': readCapability,
      range: `bytes=${range.start}-${range.endExclusive - 1}`,
    },
  });
  assert.equal(crossTenant.status, 404);

  const crossPrefix = await fetch(`${fixture.origin}/${bucket}/prefix-b/object-http`, {
    headers: {
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': readCapability,
      range: `bytes=${range.start}-${range.endExclusive - 1}`,
    },
  });
  assert.equal(crossPrefix.status, 404);

  const fullReadCapability = store.issueReadCapability({ tenant, bucket, objectId });
  const fullResponse = await fetch(objectUrl, {
    headers: {
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': fullReadCapability,
    },
  });
  assert.equal(fullResponse.status, 200);
  assert.deepEqual(Buffer.from(await fullResponse.arrayBuffer()), bytes);
});

test('loopback facade rejects an upload capability at its exact expiry boundary', async (t) => {
  const clock = new SyntheticClock();
  const store = new LocalObjectStore({ clock, maxPartBytes: 64, capabilityTtlMs: 10 });
  const fixture = await startS3Fixture({ store });
  t.after(fixture.close);
  const bytes = Buffer.from('expires');
  const objectUrl = `${fixture.origin}/expiry-bucket/expiry-object`;
  const beginResponse = await fetch(`${objectUrl}?uploads`, {
    method: 'POST',
    headers: {
      'x-ftnl-tenant': 'expiry-tenant',
      'x-ftnl-expected-sha256': sha256(bytes),
      'x-ftnl-part-count': '1',
    },
  });
  assert.equal(beginResponse.status, 200);
  const begin = await beginResponse.json();
  clock.advance(10);
  const expired = await fetch(`${objectUrl}?partNumber=1&uploadId=${begin.uploadId}`, {
    method: 'PUT',
    headers: {
      'x-ftnl-tenant': 'expiry-tenant',
      'x-ftnl-capability': begin.capability,
    },
    body: bytes,
  });
  assert.equal(expired.status, 403);
  assert.deepEqual(await expired.json(), { error: 'EXPIRED_CAPABILITY' });
});
