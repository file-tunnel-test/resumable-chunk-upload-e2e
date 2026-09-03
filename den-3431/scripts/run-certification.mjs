import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runCertification } from '../lib/certification.mjs';
import { canonicalJson } from '../lib/object-store.mjs';

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)));
const output = process.argv[2] ?? path.join(root, 'evidence', 'den-3431.json');
const exactHeadSha = process.env.DEN3431_EXACT_HEAD_SHA ?? '0'.repeat(40);
const evidence = await runCertification({
  sourcePinsPath: path.join(root, 'source-pins.json'),
  exactHeadSha,
});
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, canonicalJson(evidence) + '\n', { mode: 0o600 });
console.log(JSON.stringify({
  schema: evidence.schema,
  evidenceDigest: evidence.evidenceDigest,
  providerMode: evidence.providerMode,
  deletionStatus: evidence.lifecycle.finalDeletionEvidence,
}));
