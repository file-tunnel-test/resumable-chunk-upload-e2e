import java.nio.file.*;
public final class Verify {
  private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
  public static void main(String[] args) throws Exception {
    String text = Files.readString(Path.of(args[0]));
    require(text.contains("\"schema\":\"file-tunnel-test/object-storage-evidence/v2\""), "schema");
    require(text.contains("\"tamperDetected\":true"), "tamper");
    require(text.contains("\"staleCapabilityRejected\":true"), "stale capability");
    require(text.contains("\"reorderedPartRejected\":true"), "reordered part");
    require(text.contains("\"expiredCapabilityRejected\":true"), "expired capability");
    require(text.contains("\"wrongEtagRejected\":true"), "wrong ETag");
    require(text.contains("\"partialResponses\":1"), "partial response fault");
    require(text.contains("\"finalDeletionEvidence\":\"verified\""), "deletion");
    require(text.contains("\"tenantScopedCleanup\":true"), "tenant cleanup");
    require(!text.contains("X-Amz-Signature"), "signed URL leaked");
    System.out.println("java parity: PASS");
  }
}
