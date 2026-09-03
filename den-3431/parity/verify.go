package main
import ("encoding/json"; "fmt"; "os"; "regexp")
func must(ok bool, m string){ if !ok { panic(m) } }
func main(){
  b,e:=os.ReadFile(os.Args[1]); if e!=nil{panic(e)}
  var p map[string]any; if e=json.Unmarshal(b,&p); e!=nil{panic(e)}
  must(p["schema"]=="file-tunnel-test/object-storage-evidence/v1","schema")
  must(regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(p["exactHeadSha"].(string)),"sha")
  integrity:=p["integrity"].(map[string]any); must(integrity["tamperDetected"].(bool),"tamper")
  resume:=p["resume"].(map[string]any); must(resume["staleCapabilityRejected"].(bool),"stale")
  lifecycle:=p["lifecycle"].(map[string]any); must(lifecycle["finalDeletionEvidence"]=="verified","delete")
  isolation:=p["isolation"].(map[string]any); must(isolation["tenantScopedCleanup"].(bool),"tenant")
  bounds:=p["resourceBounds"].(map[string]any); must(bounds["peakWorkingSetBytes"].(float64)<=2*bounds["maxPartBytes"].(float64),"bounds")
  fmt.Println("go parity: PASS")
}
