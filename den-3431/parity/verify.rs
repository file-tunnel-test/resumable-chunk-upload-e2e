use std::{env, fs};
fn main() {
    let text = fs::read_to_string(env::args().nth(1).expect("path")).expect("read");
    assert!(text.contains("\"schema\":\"file-tunnel-test/object-storage-evidence/v1\""));
    assert!(text.contains("\"tamperDetected\":true"));
    assert!(text.contains("\"rangeVerified\":true"));
    assert!(text.contains("\"staleCapabilityRejected\":true"));
    assert!(text.contains("\"finalDeletionEvidence\":\"verified\""));
    assert!(text.contains("\"tenantScopedCleanup\":true"));
    assert!(!text.contains("BEGIN PRIVATE KEY"));
    println!("rust parity: PASS");
}
