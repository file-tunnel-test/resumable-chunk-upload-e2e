package main
import ("encoding/json"; "fmt"; "os"; "regexp")
func must(ok bool, m string){ if !ok { panic(m) } }
func main(){
  b,e:=os.ReadFile(os.Args[1]); if e!=nil{panic(e)}
  var p map[string]any; if e=json.Unmarshal(b,&p); e!=nil{panic(e)}
  must(p["schema"]=="file-tunnel-test/object-storage-evidence/v2","schema")
  must(regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p["exactHeadSha"].(string)),"sha")
  integrity:=p["integrity"].(map[string]any); must(integrity["tamperDetected"].(bool),"tamper")
  must(integrity["wrongEtagRejected"].(bool) && integrity["partialResponseRejected"].(bool),"completion integrity")
  encryption:=p["encryption"].(map[string]any); must(encryption["clientModeMetadataVerified"].(bool) && encryption["serverModeMetadataVerified"].(bool),"encryption modes")
  must(encryption["invalidModeRejected"].(bool) && encryption["rawKeyExcluded"].(bool),"encryption metadata")
  resume:=p["resume"].(map[string]any); must(resume["staleCapabilityRejected"].(bool),"stale")
  must(resume["expiredCapabilityRejected"].(bool),"expired")
  lifecycle:=p["lifecycle"].(map[string]any); must(lifecycle["finalDeletionEvidence"]=="verified","delete")
  isolation:=p["isolation"].(map[string]any); must(isolation["tenantScopedCleanup"].(bool),"tenant")
  must(isolation["namespaceScopedCleanup"].(bool) && isolation["cacheIsolation"].(bool),"scope")
  must(isolation["crossPrefixReadRejected"].(bool),"prefix")
  faults:=p["faultInjection"].(map[string]any); for _,k:=range []string{"disconnects","retries","delayedParts","staleListings","partialResponses"}{must(faults[k].(float64)==1,"fault "+k)}
  bounds:=p["resourceBounds"].(map[string]any); must(bounds["peakWorkingSetBytes"].(float64)<=2*bounds["maxPartBytes"].(float64),"bounds")
  fmt.Println("go parity: PASS")
}
