# DEN-3431 independent object-storage certification

This directory extends the generated `storage-e2e` repository without modifying its generated fleet files.

The default path is fully local, synthetic, and credential-free. It models an S3/R2-style multipart object boundary with AES-256-GCM authenticated parts, capability-bound resume state, deterministic fault injection, explicit lifecycle transitions, and tenant-scoped cleanup. Evidence retains only hashes and non-secret algorithm/key-version metadata.

The suite proves:

- plaintext, ciphertext, and GCM-tag integrity, including tamper and truncated-object failure;
- exact replay/idempotency, stale capability rejection, ordered multipart completion, and disconnect recovery;
- expired/stale request rejection, completion ETag binding, and truncated-object failure;
- range authorization and authenticated partial reads;
- explicit client-side and provider-managed encryption metadata without raw key material;
- key-version rotation without persisting raw keys;
- legal hold, retention, soft delete, tombstone, hard delete, and verified deletion evidence;
- negative tenant, object, capability, and cleanup scope;
- S3-style prefix isolation, including nested object keys;
- bounded part and working-set limits;
- deterministic disconnect, retry, delay, stale-listing, and partial-response faults;
- 64 deterministic model-based lifecycle traces covering 1,536 valid and invalid transition steps;
- deterministic evidence checked independently by Node, Python, Go, Java, and Rust.

An optional provider adapter can consume the same evidence schema, but no R2/S3 credentials are accepted by the default workflow.
