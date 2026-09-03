#!/usr/bin/env python3
import json, re, sys
p = json.load(open(sys.argv[1], encoding='utf-8'))
assert p['schema'] == 'file-tunnel-test/object-storage-evidence/v1'
assert re.fullmatch(r'[0-9a-f]{40}', p['exactHeadSha'])
assert p['integrity']['tamperDetected'] and p['integrity']['rangeVerified']
assert p['resume']['staleCapabilityRejected'] and p['resume']['reorderedPartRejected']
assert p['lifecycle']['finalDeletionEvidence'] == 'verified'
assert p['isolation']['tenantScopedCleanup']
assert p['resourceBounds']['peakWorkingSetBytes'] <= 2 * p['resourceBounds']['maxPartBytes']
print('python parity: PASS')
