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
  const objectId = 'object-http';
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

  for (let index = 0; index < chunks.length; index += 1) {
    const response = await fetch(`${objectUrl}?partNumber=${index + 1}&uploadId=${begin.uploadId}`, {
      method: 'PUT',
      headers: { 'x-ftnl-tenant': tenant, 'x-ftnl-capability': capability },
      body: chunks[index],
    });
    assert.equal(response.status, 200);
    capability = response.headers.get('x-ftnl-next-capability');
    assert.ok(capability);
  }

  const completeResponse = await fetch(`${objectUrl}?uploadId=${begin.uploadId}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-ftnl-tenant': tenant,
      'x-ftnl-capability': capability,
    },
    body: JSON.stringify({ expectedDigest, expectedPartCount: chunks.length }),
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
});
