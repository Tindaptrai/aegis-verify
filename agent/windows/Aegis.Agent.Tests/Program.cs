using System.Security.Cryptography;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using Aegis.Agent;
if(args.Contains("--inert-grandchild")){Thread.Sleep(Timeout.Infinite);return 0;}
if(args.Contains("--inert-child")){using var child=System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Environment.ProcessPath!,"--inert-grandchild"){UseShellExecute=false,CreateNoWindow=true});File.WriteAllText(args[1],child!.Id.ToString());Thread.Sleep(Timeout.Infinite);return 0;}
var failed = 0;
void Test(string name, Action test) { try { test(); Console.WriteLine("PASS " + name); } catch(Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.GetType().Name); } }
void Reject(Action action) { try { action(); } catch(AgentException) { return; } throw new Exception("accepted invalid input"); }
using var rsa = RSA.Create(3072);
var now = DateTimeOffset.UtcNow;
var id = Guid.NewGuid().ToString();
var hash = new string('a',64);
var pins = new Dictionary<string,string> { ["scenario_sha256"]=hash,["profile_sha256"]=hash,["runner_sha256"]=hash,["kit_sha256"]=hash,["payload_sha256"]=hash };
var payload = new Dictionary<string,object> { ["protocol"]="0.1.0",["job_id"]=id,["run_id"]=id,["agent_id"]=id,["approval_id"]=id,["environment_id"]="lab",["generation"]=1,["scenario_id"]="SCN-001",["runner_id"]="scn001-safe-demo",["runner_version"]="0.3.0",["not_before"]=Protocol.Time(now.AddSeconds(-2)),["expires_at"]=Protocol.Time(now.AddSeconds(120)),["collection_start"]=Protocol.Time(now.AddSeconds(-5)),["collection_end"]=Protocol.Time(now.AddSeconds(420)),["timeout_seconds"]=180,["parameters"]=new { run_label="A",rule_revision="baseline",rule_sha256=hash } };
foreach(var pair in pins) payload[pair.Key]=pair.Value;
byte[] Envelope() { var bytes=JsonSerializer.SerializeToUtf8Bytes(payload); return JsonSerializer.SerializeToUtf8Bytes(new { protocol="0.1.0",key_id="manager-v1",payload=Convert.ToBase64String(bytes),signature=Convert.ToBase64String(rsa.SignData(bytes,HashAlgorithmName.SHA256,RSASignaturePadding.Pss)) }); }
VerifiedJob Validate(byte[]? env=null) => Protocol.Verify(env??Envelope(),rsa,id,"lab",1,pins,new Dictionary<string,string>{{"baseline",hash},{"behavioral",hash}},false,now);
Test("valid signature",()=>Validate());
Test("tampered signature",()=> { var e=Envelope(); e[^5]=(byte)(e[^5]=='A'?'B':'A'); Reject(()=>Validate(e)); });
foreach(var field in new[]{"agent_id","generation","scenario_sha256","run_id","expires_at","timeout_seconds","foreign"}) Test("reject "+field,()=> { var had=payload.TryGetValue(field,out var old); payload[field]=field=="generation"?2:field=="timeout_seconds"?179:field=="expires_at"?Protocol.Time(now.AddSeconds(-1)):field=="foreign"?"x":Guid.NewGuid().ToString(); Reject(()=>Validate()); if(had)payload[field]=old!;else payload.Remove(field); });
Test("duplicate property",()=>Reject(()=>StrictJson.Parse("{\"a\":1,\"a\":2}"u8.ToArray())));
Test("unknown nested parameter",()=> { var old=payload["parameters"];payload["parameters"]=new {run_label="A",rule_revision="baseline",rule_sha256=hash,command="bad"};Reject(()=>Validate());payload["parameters"]=old; });
Test("HTTPS URL restrictions",()=> { foreach(var s in new[]{"http://example.test","https://user@example.test/","https://example.test/path","https://example.test/?x=1","https://example.test/#x"}) Reject(()=>Transport.ValidateOrigin(s)); Transport.ValidateOrigin("https://example.test:8443/"); });
Test("transport bounds stalled response body after partial data", () => {
    using var body = new StallingBodyStream("{\"protocol\":");
    using var client = new HttpClient(new ResponseHandler(() => { var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(body) }; response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json"); return response; })) { BaseAddress = new Uri("https://example.test/") };
    using var transport = new Transport(client, TimeSpan.FromMilliseconds(100));
    var call = transport.Post("agent/v1/poll", "{}");
    if (!Task.WhenAny(call, Task.Delay(2000)).GetAwaiter().GetResult().Equals(call)) throw new Exception("body read exceeded deadline");
    try { call.GetAwaiter().GetResult(); throw new Exception("stalled body accepted"); }
    catch (OperationCanceledException) { }
});
Test("transport bounds waiting for response headers", () => {
    using var client = new HttpClient(new StallingHeadersHandler()) { BaseAddress = new Uri("https://example.test/") };
    using var transport = new Transport(client, TimeSpan.FromMilliseconds(100));
    var call = transport.Post("agent/v1/poll", "{}");
    if (!Task.WhenAny(call, Task.Delay(2000)).GetAwaiter().GetResult().Equals(call)) throw new Exception("headers exceeded deadline");
    try { call.GetAwaiter().GetResult(); throw new Exception("stalled headers accepted"); }
    catch (OperationCanceledException) { }
});
Test("transport rejects body beyond 64 KiB", () => {
    using var client = new HttpClient(new ResponseHandler(() => {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[65537]) };
        response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
        return response;
    })) { BaseAddress = new Uri("https://example.test/") };
    using var transport = new Transport(client, TimeSpan.FromSeconds(2));
    Reject(() => transport.Post("agent/v1/poll", "{}").GetAwaiter().GetResult());
});
Test("durable lock journal recovery",()=> { var dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());Directory.CreateDirectory(dir);try {using(var j=new Journal(dir)){j.Record(Validate(),"start_requested");try{using var second=new Journal(dir);throw new Exception("lock accepted");}catch(IOException){} }using(var j=new Journal(dir)){if(j.Load(id)?.Phase!="start_requested")throw new Exception();j.Record(Validate(),"launch_intent");}using(var j=new Journal(dir)){if(j.Load(id)?.Phase!="launch_intent")throw new Exception();}}finally{Directory.Delete(dir,true);} });
if(OperatingSystem.IsWindows()) Test("owned process timeout and cleanup",()=> { var exe=Environment.ProcessPath!;var pidFile=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString()+".pid");var log=pidFile+".log";
using var unrelated=System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe,"--inert-grandchild"){UseShellExecute=false,CreateNoWindow=true});
try {var result=OwnedRunner.Run(exe,new[]{"--inert-child",pidFile},Path.GetTempPath(),TimeSpan.FromSeconds(2),CancellationToken.None,log);if(result.ExitCode==0 || !result.CleanupSucceeded)throw new Exception();if(!File.Exists(pidFile))throw new Exception("child missing");var pid=int.Parse(File.ReadAllText(pidFile));try{using var descendant=System.Diagnostics.Process.GetProcessById(pid);if(!descendant.HasExited)throw new Exception("descendant alive");}catch(ArgumentException){}if(unrelated!.HasExited)throw new Exception("unrelated killed");}finally{unrelated!.Kill();unrelated.WaitForExit();File.Delete(pidFile);File.Delete(log);} });
Test("journal receipt exact replay",()=>{var dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());try{using(var j=new Journal(dir)){var job=Validate();j.Record(job,"terminal","exact private receipt bytes");}using(var j=new Journal(dir)){if(j.Load(id)?.Receipt!="exact private receipt bytes")throw new Exception();}}finally{Directory.Delete(dir,true);}});
Test("collection bounds",()=>{var old=payload["collection_end"];payload["collection_end"]=Protocol.Time(now.AddSeconds(150));Reject(()=>Validate());payload["collection_end"]=old;});
Test("rehearsal disabled",()=>{var old=payload["parameters"];payload["parameters"]=new{run_label="Rehearsal",rule_revision="baseline",rule_sha256=hash};Reject(()=>Validate());payload["parameters"]=old;});
Test("wrong rule pin",()=>{var old=payload["parameters"];payload["parameters"]=new{run_label="A",rule_revision="baseline",rule_sha256=new string('b',64)};Reject(()=>Validate());payload["parameters"]=old;});
Test("path traversal and UNC rejected",()=>{Reject(()=>Paths.Local(@"C:\private\..\kit"));Reject(()=>Paths.Local(@"\\server\share\kit"));Reject(()=>Paths.Local(@"C:\private\kit:stream"));});
Test("lost start response reconciles after expiry without invented start",()=>{var j=Validate();var entry=new JournalEntry(j.Id,j.Digest,"start_requested",Convert.ToBase64String(j.Payload),null);using var d=StrictJson.Parse(Aegis.Agent.Program.RecoverReceipt(entry,now.AddDays(1)) is string r?System.Text.Encoding.UTF8.GetBytes(r):throw new Exception());if(d.RootElement.GetProperty("started_at").ValueKind!=JsonValueKind.Null||d.RootElement.GetProperty("state").GetString()!="execution_unknown"||d.RootElement.GetProperty("cleanup_succeeded").GetBoolean())throw new Exception();});
Test("launch intent recovery only replays terminal bytes",()=>{var j=Validate();var entry=new JournalEntry(j.Id,j.Digest,"launch_intent",Convert.ToBase64String(j.Payload),null);var r=Aegis.Agent.Program.RecoverReceipt(entry,now.AddDays(1));if(Aegis.Agent.Program.RecoverReceipt(entry with{Receipt=r},now.AddDays(2))!=r)throw new Exception();});
Test("late start authorization yields unknown receipt without invented start", () => {
    var job = Validate();
    var late = job.Expires.AddSeconds(1);
    using var receipt = StrictJson.Parse(System.Text.Encoding.UTF8.GetBytes(Aegis.Agent.Program.UnknownReceipt(job, late, late, false)));
    if (receipt.RootElement.GetProperty("state").GetString() != "execution_unknown" ||
        receipt.RootElement.GetProperty("started_at").ValueKind != JsonValueKind.Null ||
        receipt.RootElement.GetProperty("exit_code").ValueKind != JsonValueKind.Null ||
        receipt.RootElement.GetProperty("cleanup_succeeded").GetBoolean()) throw new Exception("late start was claimed");
});
Test("observed start remains on overdue unknown receipt", () => {
    var job = Validate();
    var observedStart = job.NotBefore.AddSeconds(1);
    var finish = observedStart.AddSeconds(job.Timeout + 1);
    using var receipt = StrictJson.Parse(System.Text.Encoding.UTF8.GetBytes(Aegis.Agent.Program.UnknownReceipt(job, observedStart, finish, true)));
    if (receipt.RootElement.GetProperty("state").GetString() != "execution_unknown" ||
        receipt.RootElement.GetProperty("started_at").GetString() != Protocol.Time(observedStart) ||
        receipt.RootElement.GetProperty("exit_code").ValueKind != JsonValueKind.Null ||
        !receipt.RootElement.GetProperty("cleanup_succeeded").GetBoolean()) throw new Exception("observed start lost");
});
Test("launch boundary rejects expiry during catalog checks", () => {
    var job = Validate();
    var started = job.NotBefore.AddSeconds(1);
    var launchClock = job.Expires.AddSeconds(1);
    Reject(() => Aegis.Agent.Program.LaunchRemaining(job, started, launchClock));
});
Test("launch boundary retains timeout remaining within lease", () => {
    var job = Validate();
    var started = job.NotBefore.AddSeconds(1);
    var launchClock = started.AddSeconds(3);
    if (Aegis.Agent.Program.LaunchRemaining(job, started, launchClock) !=
        TimeSpan.FromSeconds(job.Timeout - 3)) throw new Exception("incorrect launch budget");
});
Test("catalog exact bytes and expected host",()=>{
var dir=Path.Combine(Path.GetTempPath(),Guid.NewGuid().ToString());Directory.CreateDirectory(dir);
try{string Put(string name,string text){var p=Path.Combine(dir,name);File.WriteAllText(p,text);return p;}var scenario=Put("scenario.yaml","synthetic scenario");var profile=Put("profile.json","{}");var runner=Put("runner.ps1","inert fixture never executed");var publicKey=Put("public.pem",rsa.ExportSubjectPublicKeyInfoPem());
var artifact=Put("lab_update.ps1","inert payload");Put("maintenance_check.ps1","inert payload");var baseline=Put("baseline.xml","inert rule");Put("behavioral.xml","inert rule");
string H(string p)=>Protocol.Hash(File.ReadAllBytes(p));var manifest=Put("kit.json",JsonSerializer.Serialize(new{target_host=Environment.MachineName,lab_directory=dir,payload_sha256=H(artifact),kit_version="0.3.0",scenario_id="SCN-001"}));
var catalog=new Dictionary<string,object>{{"scenario_path",scenario},{"profile_path",profile},{"runner_path",runner},{"kit_directory",dir},{"run_directory",dir},{"expected_computer_name",Environment.MachineName},{"allow_rehearsal",false},{"scenario_sha256",H(scenario)},{"profile_sha256",H(profile)},{"runner_sha256",H(runner)},{"kit_sha256",H(manifest)},{"payload_sha256",H(artifact)},{"baseline_sha256",H(baseline)},{"behavioral_sha256",H(baseline)}};
var config=new Dictionary<string,object>{{"manager_url","https://example.test/"},{"agent_id",id},{"environment_id","lab"},{"generation",1},{"client_certificate_sha256",hash},{"signing_public_key_path",publicKey},{"spool_directory",dir},{"catalog",catalog}};var path=Put("private.json",JsonSerializer.Serialize(config));using(var c=new Configuration(path))c.CheckFiles();File.AppendAllText(manifest," ");Reject(()=>{using var c=new Configuration(path);});catalog["kit_sha256"]=H(manifest);catalog["expected_computer_name"]="OTHER_HOST";File.WriteAllText(path,JsonSerializer.Serialize(config));Reject(()=>{using var c=new Configuration(path);});
}finally{Directory.Delete(dir,true);}});
return failed==0?0:1;

sealed class ResponseHandler(Func<HttpResponseMessage> response) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(response());
}

sealed class StallingHeadersHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        throw new Exception("unreachable");
    }
}

sealed class StallingBodyStream(string prefix) : Stream
{
    readonly byte[] bytes = System.Text.Encoding.UTF8.GetBytes(prefix);
    bool sent;
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (!sent) { sent = true; bytes.CopyTo(buffer); return bytes.Length; }
        await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        return 0;
    }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
