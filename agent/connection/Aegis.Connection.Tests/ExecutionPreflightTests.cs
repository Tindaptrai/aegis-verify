using Aegis.Connection;
using Aegis.Connection.Execution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;

internal static partial class Program
{
    private static void ExecutionPreflightTests()
    {
        Test("execution preflight profile signing key is exactly RSA3072", () =>
        {
            var (grant, facts) = PreflightFixture();
            facts.Files[@"C:\Reviewed\profile.json"] = ExecutionProtocol.CanonicalBytes(grant.Profile);
            facts.Files[@"C:\Reviewed\grant.json"] = ExecutionProtocol.CanonicalBytes(grant.Installed);
            foreach (var size in new[] { 2048, 3072, 4096 })
            {
                using var key = RSA.Create(size);
                facts.Files[@"C:\Reviewed\public.pem"] = Encoding.ASCII.GetBytes(key.ExportSubjectPublicKeyInfoPem());
                ExecutionGrant Load() => ExecutionProfile.Load(@"C:\Reviewed\profile.json", @"C:\Reviewed\grant.json", @"C:\Reviewed\public.pem", grant.Identity, facts.ReadImmutable);
                if (size == 3072) Check(Load().PublicKeySha256 == ExecutionProfile.Hash(key.ExportSubjectPublicKeyInfo()), "RSA3072 profile key rejected");
                else Denied(() => Load(), "execution_invalid");
            }
        });
        Test("execution preflight clock bound and conservative expiry", () =>
        {
            var sent = DateTimeOffset.Parse("2026-10-25T12:00:00Z");
            var utc = sent;
            var clock = new ExecutionClock(() => utc);
            Check(!clock.IsCertain(TimeSpan.Zero), "unobserved clock accepted");
            clock.Observe(sent.AddSeconds(4), sent, TimeSpan.Zero, TimeSpan.Zero);
            Check(clock.IsCertain(TimeSpan.Zero), "5s exact upper offset rejected");
            Check(!clock.IsCertain(TimeSpan.FromTicks(1)), "5s epsilon accepted");
            clock.Observe(sent, sent, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
            utc = sent.AddSeconds(1);
            Check(clock.TryGetBounds(TimeSpan.FromSeconds(2), out var bounds), "fresh bounds absent");
            Check(bounds.EarliestUtc <= sent.AddSeconds(1) && bounds.LatestUtc >= sent.AddSeconds(2), "interval lost server precision");
            Check(!clock.IsCertain(TimeSpan.FromSeconds(17)), "old sample accepted");
            clock.Observe(sent, sent, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(2));
            Check(!clock.IsCertain(TimeSpan.FromSeconds(3)), "out of order sample accepted");
        });
        Test("execution preflight clock jump and negative monotonic fail closed", () =>
        {
            var sent = DateTimeOffset.Parse("2026-10-25T12:00:00Z"); var utc = sent;
            var clock = new ExecutionClock(() => utc);
            clock.Observe(sent, sent, TimeSpan.Zero, TimeSpan.Zero);
            utc = sent.AddHours(1);
            Check(!clock.IsCertain(TimeSpan.FromSeconds(1)), "UTC jump accepted");
            utc = sent.AddSeconds(2);
            Check(!clock.IsCertain(TimeSpan.FromSeconds(2)), "clock jump forgotten without authenticated observation");
            Check(!clock.IsCertain(TimeSpan.FromSeconds(-1)), "negative clock accepted");
        });
        Test("execution preflight explicit missing grant never becomes ready", () =>
        {
            var identity = new IdentityState("enrolled", "https://synthetic.invalid", "unused", "unused", "unused",
                "SYNTHETIC", "windows", "x64", "0.3.0");
            Denied(() => ExecutionProfile.Load("missing-profile", "missing-grant", "missing-key", identity));
        });
        Test("execution preflight local native path rejects aliases and traversal", () =>
        {
            foreach (var path in new[] { @"\\server\share\script.ps1", @"C:\kit\..\script.ps1", @"C:\kit\x.ps1:stream", @"C:\kit\CON.ps1", @"C:\kit\trailing.\x.ps1", @"C:\kit\é.ps1" })
                Denied(() => ExecutionProfile.LocalPath(path));
            ExecutionProfile.LocalPath(@"C:\Reviewed\script.ps1");
        });
        Test("execution preflight immutable ACL allows read execute and rejects mutation",()=>
        {
            if(!OperatingSystem.IsWindows())return;
            Check(!ExecutionProfile.GrantsMutation(System.Security.AccessControl.FileSystemRights.ReadAndExecute|System.Security.AccessControl.FileSystemRights.Synchronize),"read execute treated as mutation");
            foreach(var rights in new[]{System.Security.AccessControl.FileSystemRights.Modify,System.Security.AccessControl.FileSystemRights.Delete,System.Security.AccessControl.FileSystemRights.ChangePermissions,System.Security.AccessControl.FileSystemRights.WriteData})
                Check(ExecutionProfile.GrantsMutation(rights),"mutation accepted");
        });
        Test("execution preflight event variant reads Boolean type and scalar value",()=>
        {
            var buffer=Marshal.AllocHGlobal(16);
            try
            {
                void Write(int value,int count,int type)
                {
                    Marshal.WriteInt64(buffer,0,0); Marshal.WriteInt32(buffer,0,value);
                    Marshal.WriteInt32(buffer,8,count); Marshal.WriteInt32(buffer,12,type);
                }
                Write(1,0,13); Check(NativeExecutionFacts.EnabledScalarBoolean(buffer),"enabled scalar rejected");
                Write(1,37,13); Check(NativeExecutionFacts.EnabledScalarBoolean(buffer),"unused scalar Count treated as type/enabled");
                Write(0,13,13); Check(!NativeExecutionFacts.EnabledScalarBoolean(buffer),"disabled scalar accepted");
                Write(1,13,8); Check(!NativeExecutionFacts.EnabledScalarBoolean(buffer),"UInt32 accepted as Boolean");
                Write(1,13,13|0x80); Check(!NativeExecutionFacts.EnabledScalarBoolean(buffer),"Boolean array accepted as scalar");
            }
            finally {Marshal.FreeHGlobal(buffer);}
        });
        Test("execution preflight unsupported and unknown policy fail closed", () =>
        {
            var facts = new SyntheticExecutionFacts();
            var result = ExecutionPreflight.Check(null!, facts);
            Check(!result.Ready, "missing grant accepted");
            facts.Supported = false;
            Check(ExecutionPreflight.Check(null!, facts).BlockingCodes.Contains("unsupported_platform"), "Linux accepted");
        });
        Test("execution preflight actual artifacts and study drift block", () =>
        {
            var (grant,facts)=PreflightFixture();
            ExecutionPreflight.CheckArtifacts(grant,facts);
            Check(ExecutionPreflight.Check(grant,facts).Ready,"synthetic reviewed set rejected");
            var path=grant.Profile.KitDirectory+"\\maintenance_check.ps1";
            facts.Files[path]=Encoding.ASCII.GetBytes("Write-Output 'changed'\n");
            Check(ExecutionPreflight.Check(grant,facts).BlockingCodes.Contains("artifact_mismatch"),"payload drift accepted");
            (grant,facts)=PreflightFixture(); facts.Policy=false;
            Check(ExecutionPreflight.Check(grant,facts).BlockingCodes.Contains("local_not_ready"),"unknown policy accepted");
            facts.Policy=true; facts.Telemetry=false;
            Check(!ExecutionPreflight.Check(grant,facts).Ready,"missing prior event accepted");
            facts.Telemetry=true; facts.Host="OTHER";
            Check(!ExecutionPreflight.Check(grant,facts).Ready,"host drift accepted");
        });
        Test("execution preflight load binds separate profile grant identity and public key", () =>
        {
            var (grant,facts)=PreflightFixture(); using var key=RSA.Create(3072);
            facts.Files[@"C:\Reviewed\profile.json"]=ExecutionProtocol.CanonicalBytes(grant.Profile);
            facts.Files[@"C:\Reviewed\grant.json"]=ExecutionProtocol.CanonicalBytes(grant.Installed);
            facts.Files[@"C:\Reviewed\public.pem"]=Encoding.ASCII.GetBytes(key.ExportSubjectPublicKeyInfoPem());
            var loaded=ExecutionProfile.Load(@"C:\Reviewed\profile.json",@"C:\Reviewed\grant.json",@"C:\Reviewed\public.pem",grant.Identity,facts.ReadImmutable);
            Check(loaded.PublicKeySha256==Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo())),"SPKI pin not derived from local key");
            facts.Files[@"C:\Reviewed\grant.json"]=ExecutionProtocol.CanonicalBytes(grant.Installed with {BindingRevision=2,InstallationProfileSha256=new string('f',64)});
            Denied(()=>ExecutionProfile.Load(@"C:\Reviewed\profile.json",@"C:\Reviewed\grant.json",@"C:\Reviewed\public.pem",grant.Identity,facts.ReadImmutable));
        });
        Test("execution preflight rejects self consistent unsupported scenario bytes",()=>
        {
            var (grant,facts)=PreflightFixture(false);
            Check(ExecutionPreflight.Check(grant,facts).BlockingCodes.Contains("artifact_mismatch"),"marker-only scenario accepted with self-consistent pins");
        });
        Test("execution preflight upgrades retain enrolled version while checking actual build",()=>
        {
            var (grant,facts)=PreflightFixture();
            grant=grant with {Identity=grant.Identity with {AgentVersion="0.2.0"}};
            Check(ExecutionPreflight.Check(grant,facts).Ready,"unchanged enrolled version blocked upgraded build");
            facts.BuildVersion="0.2.0";
            Check(!ExecutionPreflight.Check(grant,facts).Ready,"presence-only running build accepted");
        });
        Test("execution preflight entire clock interval must fit launch window", () =>
        {
            var (grant,facts)=PreflightFixture(); var now=DateTimeOffset.UtcNow.AddSeconds(-10); now=now.AddTicks(-(now.Ticks%TimeSpan.TicksPerSecond));
            var utc=now; var clock=new ExecutionClock(()=>utc); clock.Observe(now,now,TimeSpan.Zero,TimeSpan.Zero);
            string Stamp(DateTimeOffset dt)=>dt.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
            var pins=grant.Profile.ArtifactPins; var id=Guid.NewGuid().ToString();
            var job=new SignedJob(ExecutionProtocol.Version,id,id,grant.Installed.DeviceId,grant.Installed.CertificateSha256,Guid.NewGuid().ToString(),
                grant.Profile.EnvironmentId,1,grant.Installed.BindingId,1,1,new string('a',64),"SCN-001","scn001-safe-demo","0.3.0",
                pins.ScenarioSha256,pins.ProfileSha256,pins.RunnerSha256,pins.KitSha256,pins.PayloadSha256,
                Stamp(now),Stamp(now.AddSeconds(120)),Stamp(now.AddSeconds(-30)),Stamp(now.AddSeconds(300)),180,new("A","baseline",grant.Profile.RulePins.Baseline));
            Check(ExecutionPreflight.CheckBeforeLaunch(job,grant,clock,TimeSpan.Zero,facts).Ready,"inside interval blocked");
            clock.Observe(now.AddSeconds(119),now.AddSeconds(119),TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(1)); utc=now.AddSeconds(119);
            Check(ExecutionPreflight.CheckBeforeLaunch(job,grant,clock,TimeSpan.FromSeconds(1),facts).BlockingCodes.Contains("clock_uncertain"),"upper bound at expiry accepted");
        });
    }
    private sealed class SyntheticExecutionFacts : IExecutionFacts
    {
        public bool Supported { get; set; } = true;
        public string BuildVersion {get;set;}="0.3.0";
        public string ExecutionBuildVersion => BuildVersion;
        public string Host { get; set; }="SYNTHETIC";
        public string ComputerName => Host;
        public string PowerShellPath => @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        public bool ServiceIdentity => true;
        public bool Telemetry {get;set;}=true;
        public bool Policy {get;set;}=true;
        public Dictionary<string,byte[]> Files {get;}=new(StringComparer.Ordinal);
        public Action? BeforeRead { get; set; }
        public bool TelemetryReadable() => Telemetry;
        public bool PolicyAllows(ExecutionGrant grant) => Policy;
        public byte[] ReadImmutable(string path) { BeforeRead?.Invoke(); return Files.TryGetValue(path,out var raw) ? (byte[])raw.Clone() : throw new ConnectionException("execution_invalid"); }
        public void ValidateRunParent(string path) { }
    }
    private static (ExecutionGrant,SyntheticExecutionFacts) PreflightFixture(bool supportedScenario=true)
    {
        var facts=new SyntheticExecutionFacts(); var kit=@"C:\Reviewed\Kit";
        byte[] Bytes(object value)=>ExecutionProtocol.CanonicalBytes(value);
        string Hash(byte[] raw)=>Convert.ToHexStringLower(SHA256.HashData(raw));
        string Wire(string value)=>JsonSerializer.Serialize(value)[1..^1];
        var payload=Encoding.ASCII.GetBytes("$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }\nWrite-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $facts.Pid)\n");
        var cases=new[]{"comment-only","env-only","fragmented","marker-only","missing-counter","missing-text","original","pid-only","renamed","reworded","unrelated","wrong-channel","wrong-event-id","wrong-host","wrong-provider"};
        var artifacts=new Dictionary<string,byte[]>{["lab_update.ps1"]=payload,["maintenance_check.ps1"]=payload,["Invoke-SafeDemo.ps1"]=Encoding.ASCII.GetBytes("# synthetic pinned runner"),["baseline.xml"]=Encoding.ASCII.GetBytes("synthetic-baseline"),["behavioral.xml"]=Encoding.ASCII.GetBytes("synthetic-behavioral"),["fixed.xml"]=Encoding.ASCII.GetBytes("synthetic-fixed"),["logtest-cases/catalog.json"]=Encoding.ASCII.GetBytes("{}")};
        foreach(var name in cases)artifacts["logtest-cases/"+name+".synthetic.json"]=Encoding.ASCII.GetBytes("{}");
        foreach(var (name,raw) in artifacts)facts.Files[kit+"\\"+name.Replace('/','\\')]=raw;
        // Canonical Git blob bytes, independent of this Windows checkout's CRLF.
        var scenario=supportedScenario ? Convert.FromBase64String("IyBEcmFmdCBtYW5pZmVzdC4gSXNzdWUgIzIgd2lsbCBmb3JtYWxpemUgYW5kIHZhbGlkYXRlIHRoZSBzY2VuYXJpbyBzY2hlbWEuCmlkOiBTQ04tMDAxCm5hbWU6IFBvd2VyU2hlbGwgRXhlY3V0aW9uCnZlcnNpb246IDAuMS4wCnN0YXR1czogZHJhZnQKZGVzY3JpcHRpb246ID4tCiAgRXhlY3V0ZSBhbiBhcHByb3ZlZCwgbm9uLWRlc3RydWN0aXZlIFBvd2VyU2hlbGwgdGVzdCBzY3JpcHQgYW5kIHZlcmlmeSB0aGF0CiAgZW5kcG9pbnQgdGVsZW1ldHJ5IGFuZCB0aGUgZXhwZWN0ZWQgV2F6dWggZGV0ZWN0aW9uIGFyZSBwcmVzZW50LgpzYWZldHk6CiAgZGVzdHJ1Y3RpdmU6IGZhbHNlCiAgYXV0aG9yaXphdGlvbl9yZXF1aXJlZDogdHJ1ZQogIG5vdGVzOiBSdW4gb25seSBpbiB0aGUgYXBwcm92ZWQgbGFiIHdpdGggYSByZXZpZXdlZCB0ZXN0IHBheWxvYWQuCmV4cGVjdGVkX3NvdXJjZXM6CiAgLSBzeXNtb24KICAtIHBvd2Vyc2hlbGwKICAtIHdhenVoCmV4cGVjdGVkX291dGNvbWU6IGRldGVjdGVkCmFzc2VydGlvbnM6CiAgLSBpZDogU0NOLTAwMS1BMDEKICAgIGRlc2NyaXB0aW9uOiBQb3dlclNoZWxsIHByb2Nlc3MgZXhlY3V0aW9uIHRlbGVtZXRyeSBleGlzdHMuCiAgICBzb3VyY2U6IHN5c21vbgogIC0gaWQ6IFNDTi0wMDEtQTAyCiAgICBkZXNjcmlwdGlvbjogUG93ZXJTaGVsbCBzY3JpcHQgb3IgY29tbWFuZCB0ZWxlbWV0cnkgZXhpc3RzLgogICAgc291cmNlOiBwb3dlcnNoZWxsCiAgLSBpZDogU0NOLTAwMS1BMDMKICAgIGRlc2NyaXB0aW9uOiBXYXp1aCBkZXRlY3Rpb24gcmVmZXJlbmNlcyB0aGUgZXhlY3V0aW9uIGV2aWRlbmNlLgogICAgc291cmNlOiB3YXp1aAp0YWdzOgogIC0gcmVncmVzc2lvbi1kZW1vCiAgLSBnYXAtZml4LXJldGVzdAo=") : Encoding.ASCII.GetBytes("id: SCN-001\nversion: 0.1.0\nexpected_outcome: detected\nassertions:\n  - id: SCN-001-A01\n  - id: SCN-001-A02\n  - id: SCN-001-A03\n");
        var paths=new[]{Wire(kit+"\\lab_update.ps1"),Wire(kit+"\\maintenance_check.ps1")};
        var commands=paths.Select(p=>"synthetic -File "+p).ToArray();
        object Pred(string field,string op,string? value=null,string? binding=null,string[]? values=null)=>new {field,op,value,binding,values};
        object[] Scope(string provider)=>[Pred("hostname","eq",binding:"target_host"),Pred("asset_id","eq",binding:"target_agent"),Pred("event_provider","eq",provider)];
        var pathPred=Pred("file_path","in",values:paths);
        var profile=Bytes(new {profile_schema_version="0.1.0",profile_id="synthetic",profile_version="0.1.0",scenario_id="SCN-001",scenario_version="0.1.0",scenario_fingerprint=new string('a',64),rules=new object[]{
            new {assertion_id="SCN-001-A01",role="telemetry",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-Sysmon"),match=new[]{Pred("process_name","eq",Wire(facts.PowerShellPath)),Pred("command_line","in",values:commands)}},
            new {assertion_id="SCN-001-A02",role="telemetry",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-PowerShell"),match=new[]{pathPred}},
            new {assertion_id="SCN-001-A03",role="detection",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-PowerShell"),match=new[]{pathPred,Pred("rule_id","exists"),Pred("rule_id","eq","119901")},correlation=new {anchor_assertion_id="SCN-001-A01",join_pairs=new[]{"hostname","asset_id","process_id"}.Select(k=>new {target_field=k,anchor_field=k}).ToArray(),min_delta_ns=-5000000000L,max_delta_ns=15000000000L}}}});
        var kitBytes=Bytes(new {kind="safe_demo_kit",kit_version="0.3.0",scenario_id="SCN-001",scenario_version="0.1.0",target_host="SYNTHETIC",lab_directory=kit,filenames=new[]{"lab_update.ps1","maintenance_check.ps1"},rule_id=119901,parent_sid=91816,field_profile="wazuh-eventchannel-4.14.4-lf-v1",occupied_ids_declared=Array.Empty<int>(),payload_sha256=Hash(payload),artifact_sha256=artifacts.ToDictionary(k=>k.Key,v=>Hash(v.Value))});
        var pins=new ArtifactPins(Hash(scenario),Hash(profile),Hash(artifacts["Invoke-SafeDemo.ps1"]),Hash(kitBytes),Hash(payload));
        var rules=new RulePins(Hash(artifacts["baseline.xml"]),Hash(artifacts["behavioral.xml"]));
        var study=Bytes(new {kind="scn001_study",version="0.1.0",study_id="synthetic",collection_reference="synthetic",time_reference="synthetic",pins=new {scenario=pins.ScenarioSha256,profile=pins.ProfileSha256,runner=pins.RunnerSha256,kit=pins.KitSha256,payload=pins.PayloadSha256,baseline=rules.Baseline,behavioral=rules.Behavioral,@fixed=Hash(artifacts["fixed.xml"])},target=new {environment_id="synthetic",hostname="SYNTHETIC",agent_id="901",account=@"SYNTHETIC\service",elevated=false,executable=facts.PowerShellPath,canonical_executable=Wire(facts.PowerShellPath),collection_mode="direct",native_directory=kit,canonical_paths=paths,command_lines=commands,rule_id=119901,parent_sid=91816,field_profile="wazuh-eventchannel-4.14.4-lf-v1"}});
        var installation=new InstallationProfile(1,ExecutionProtocol.ProviderId,"synthetic","SYNTHETIC",@"C:\Reviewed\scenario.yaml",@"C:\Reviewed\evaluation.json",kit+"\\Invoke-SafeDemo.ps1",kit,@"C:\Runs",@"C:\Reviewed\study.json",Hash(study),pins,rules,false,180);
        facts.Files[installation.ScenarioPath]=scenario;facts.Files[installation.ProfilePath]=profile;facts.Files[installation.StudyPath]=study;facts.Files[kit+"\\kit.json"]=kitBytes;
        using var key=RSA.Create(3072); var request=new CertificateRequest("CN=synthetic",key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var certificate=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddDays(1));
        var installed=new InstalledGrant(1,Guid.NewGuid().ToString(),1,Hash(certificate.RawData),Guid.NewGuid().ToString(),1,Hash(Bytes(installation)),Hash(Bytes(new {ArtifactPins=pins,RulePins=rules})));
        var identity=new IdentityState("enrolled","https://synthetic.invalid","unused","unused","unused","SYNTHETIC","windows","x64","0.3.0",installed.DeviceId,"synthetic",1,certificate.ExportCertificatePem());
        return(new(installation,installed,identity,new string('a',64)),facts);
    }
}
