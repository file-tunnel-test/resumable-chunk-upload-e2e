import http from 'node:http';
import { URL } from 'node:url';
import { LocalObjectStore, StoreError } from './object-store.mjs';

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new StoreError('PART_SIZE_LIMIT'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function json(response, status, value, headers = {}) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'content-type': 'application/json',
    'content-length': body.length,
    'cache-control': 'no-store',
    ...headers,
  });
  response.end(body);
}

function errorStatus(error) {
  if (!(error instanceof StoreError)) return 500;
  if (['TENANT_SCOPE', 'RANGE_SCOPE', 'CAPABILITY_CONTEXT_MISMATCH'].includes(error.code)) return 404;
  if (['EXPIRED_CAPABILITY', 'STALE_CAPABILITY', 'INVALID_CAPABILITY'].includes(error.code)) return 403;
  if (error.code === 'OBJECT_NOT_FOUND' || error.code === 'UNKNOWN_UPLOAD') return 404;
  return 409;
}

function parsePath(url) {
  const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
  if (parts.length < 2) throw new StoreError('INVALID_IDENTIFIER');
  return { bucket: parts[0], objectId: parts.slice(1).join('/') };
}

export async function startS3Fixture({ store = new LocalObjectStore(), host = '127.0.0.1', port = 0 } = {}) {
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, `http://${host}`);
      const { bucket, objectId } = parsePath(url);
      const tenant = request.headers['x-ftnl-tenant'];
      if (typeof tenant !== 'string') throw new StoreError('TENANT_SCOPE');

      if (request.method === 'POST' && url.searchParams.has('uploads')) {
        const result = store.beginUpload({
          tenant,
          bucket,
          objectId,
          expectedDigest: String(request.headers['x-ftnl-expected-sha256'] ?? ''),
          expectedPartCount: Number(request.headers['x-ftnl-part-count']),
          keyVersion: Number(request.headers['x-ftnl-key-version'] ?? 1),
          encryptionMode: String(
            request.headers['x-ftnl-encryption-mode'] ?? 'client-side-aes-256-gcm',
          ),
          retentionUntilMs: Number(request.headers['x-ftnl-retention-until-ms'] ?? store.clock.now()),
          legalHold: request.headers['x-ftnl-legal-hold'] === 'true',
        });
        json(response, 200, result);
        return;
      }

      if (request.method === 'PUT' && url.searchParams.has('partNumber')) {
        const uploadId = url.searchParams.get('uploadId');
        const partNumber = Number(url.searchParams.get('partNumber'));
        const capability = request.headers['x-ftnl-capability'];
        const body = await readBody(request, store.maxPartBytes);
        const result = store.uploadPart({ tenant, uploadId, capability, partNumber, bytes: body });
        json(response, 200, {
          replayed: result.replayed,
          nextPartNumber: result.nextPartNumber,
          inventoryDigest: result.inventoryDigest,
        }, {
          'x-ftnl-next-capability': result.capability,
          etag: `"${result.etag}"`,
        });
        return;
      }

      if (request.method === 'POST' && url.searchParams.has('uploadId')) {
        const uploadId = url.searchParams.get('uploadId');
        const capability = request.headers['x-ftnl-capability'];
        const body = JSON.parse((await readBody(request, 16 * 1024)).toString('utf8'));
        const result = store.complete({
          tenant,
          uploadId,
          capability,
          expectedDigest: body.expectedDigest,
          expectedPartCount: body.expectedPartCount,
          expectedPartEtags: body.expectedPartEtags ?? null,
        });
        json(response, 200, result);
        return;
      }

      if (request.method === 'GET') {
        const rangeHeader = request.headers.range;
        let start = 0;
        let endExclusive = null;
        if (typeof rangeHeader === 'string') {
          const match = /^bytes=(\d+)-(\d+)$/.exec(rangeHeader);
          if (!match) throw new StoreError('INVALID_RANGE');
          start = Number(match[1]);
          endExclusive = Number(match[2]) + 1;
        }
        const capability = request.headers['x-ftnl-capability'];
        const body = store.readRange({ tenant, bucket, objectId, capability, start, endExclusive });
        response.writeHead(rangeHeader ? 206 : 200, {
          'content-type': 'application/octet-stream',
          'content-length': body.length,
          'cache-control': 'no-store',
          ...(rangeHeader ? { 'content-range': `bytes ${start}-${start + body.length - 1}/*` } : {}),
        });
        response.end(body);
        return;
      }
      json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    } catch (error) {
      json(response, errorStatus(error), { error: error.code ?? 'INTERNAL_ERROR' });
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('fixture did not bind TCP');
  return {
    store,
    origin: `http://${host}:${address.port}`,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}
