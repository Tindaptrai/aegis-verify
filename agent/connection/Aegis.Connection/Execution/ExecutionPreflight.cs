using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Globalization;

namespace Aegis.Connection.Execution;

internal interface IExecutionFacts
{
    bool Supported { get; }
    string ExecutionBuildVersion { get; }
    string ComputerName { get; }
    string PowerShellPath { get; }
    bool ServiceIdentity { get; }
    byte[] ReadImmutable(string path);
    void ValidateRunParent(string path);
    bool TelemetryReadable();
    bool PolicyAllows(ExecutionGrant grant);
}

public static class ExecutionPreflight
{
    // SHA256 of the reviewed SCN-001 0.1.0 Git blob (887 raw LF bytes).
    // Provision these exact bytes; checkout newline conversion is not authority.
    public const string ReviewedScenarioSha256="4f00335ddd0e39979d90852122642b945faa03ba50d7e9189fe282662bad84a9";
    private static readonly byte[] Payload = Encoding.ASCII.GetBytes("$facts = @{ Host = $env:COMPUTERNAME; User = $env:USERNAME; Pid = $PID }\nWrite-Output 'AEGIS_SAFE_DEMO_V1'\nWrite-Output ('AEGIS_PID=' + $facts.Pid)\n");
    public static LocalReadiness Check(ExecutionGrant grant) => Check(grant,new NativeExecutionFacts());
    internal static LocalReadiness Check(ExecutionGrant grant, IExecutionFacts facts)
    {
        var codes = ImmutableArray.CreateBuilder<string>();
        var profileHash = grant?.Installed.InstallationProfileSha256 ?? string.Empty;
        var artifactHash = grant?.Installed.ArtifactSetSha256 ?? string.Empty;
        if (!facts.Supported) codes.Add("unsupported_platform");
        try
        {
            if (grant == null) throw new ConnectionException("execution_invalid");
            ExecutionProfile.ValidateGrant(grant);
            profileHash = ExecutionProfile.Hash(ExecutionProtocol.CanonicalBytes(grant.Profile));
            if (facts.ExecutionBuildVersion != "0.3.0" || grant.Profile.ExpectedComputerName != facts.ComputerName || !facts.ServiceIdentity)
                codes.Add("local_not_ready");
            using var certificate = X509Certificate2.CreateFromPem(grant.Identity.CertificatePem!);
            if (DateTimeOffset.UtcNow < certificate.NotBefore.ToUniversalTime() || DateTimeOffset.UtcNow >= certificate.NotAfter.ToUniversalTime()) codes.Add("local_not_ready");
        }
        catch (Exception e) when (SafeFailure(e)) { codes.Add("profile_mismatch"); }
        if (grant != null)
        {
            try { artifactHash = CheckArtifacts(grant, facts); }
            catch (Exception e) when (SafeFailure(e)) { codes.Add("artifact_mismatch"); }
            try
            {
                facts.ValidateRunParent(grant.Profile.RunDirectory);
                if (!facts.TelemetryReadable() || !facts.PolicyAllows(grant)) codes.Add("local_not_ready");
            }
            catch (Exception e) when (SafeFailure(e)) { codes.Add("local_not_ready"); }
        }
        return new(codes.Count==0,codes.Distinct().ToImmutableArray(),profileHash,artifactHash);
    }
    private static bool SafeFailure(Exception e) => e is ConnectionException or IOException or UnauthorizedAccessException or ArgumentException or
        InvalidOperationException or JsonException or KeyNotFoundException or System.Security.Cryptography.CryptographicException or OverflowException;

    public static LocalReadiness CheckBeforeLaunch(SignedJob job, ExecutionGrant grant, ExecutionClock clock, TimeSpan nowMonotonic)
        => CheckBeforeLaunch(job,grant,clock,nowMonotonic,new NativeExecutionFacts());
    internal static LocalReadiness CheckBeforeLaunch(SignedJob job, ExecutionGrant grant, ExecutionClock clock, TimeSpan nowMonotonic, IExecutionFacts facts)
    {
        var result = Check(grant,facts);
        var codes = result.BlockingCodes.ToBuilder();
        if (!clock.TryGetBounds(nowMonotonic,out var bounds)) codes.Add("clock_uncertain");
        else
        {
            try
            {
                var parsed = ExecutionProtocol.Decode<SignedJob>(ExecutionProtocol.CanonicalBytes(job));
                var notBefore = DateTimeOffset.ParseExact(parsed.NotBefore,"yyyy-MM-dd'T'HH:mm:ss'Z'",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal);
                var expires = DateTimeOffset.ParseExact(parsed.ExpiresAt,"yyyy-MM-dd'T'HH:mm:ss'Z'",CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal);
                if (bounds.EarliestUtc < notBefore || bounds.LatestUtc >= expires) codes.Add("clock_uncertain");
                var pins = grant.Profile.ArtifactPins;
                if (job.DeviceId != grant.Installed.DeviceId || job.Generation != grant.Installed.Generation || job.CertificateSha256 != grant.Installed.CertificateSha256 ||
                    job.BindingId != grant.Installed.BindingId || job.BindingRevision != grant.Installed.BindingRevision || job.EnvironmentId != grant.Profile.EnvironmentId ||
                    job.TimeoutSeconds != grant.Profile.TimeoutSeconds || job.ScenarioSha256 != pins.ScenarioSha256 || job.ProfileSha256 != pins.ProfileSha256 ||
                    job.RunnerSha256 != pins.RunnerSha256 || job.KitSha256 != pins.KitSha256 || job.PayloadSha256 != pins.PayloadSha256 ||
                    job.Parameters.RuleSha256 != (job.Parameters.RuleRevision=="baseline" ? grant.Profile.RulePins.Baseline : grant.Profile.RulePins.Behavioral) ||
                    job.Parameters.RunLabel=="Rehearsal" && !grant.Profile.AllowRehearsal) codes.Add("profile_mismatch");
            }
            catch (Exception e) when (SafeFailure(e)) { codes.Add("profile_mismatch"); }
        }
        return result with { Ready=codes.Count==0,BlockingCodes=codes.Distinct().ToImmutableArray() };
    }

    internal static string CheckArtifacts(ExecutionGrant grant, IExecutionFacts facts)
    {
        var p=grant.Profile;
        foreach (var path in new[]{p.ScenarioPath,p.ProfilePath,p.RunnerPath,p.StudyPath}) ExecutionProfile.LocalPath(path);
        ExecutionProfile.LocalPath(p.KitDirectory,200); ExecutionProfile.LocalPath(p.RunDirectory,206);
        if (p.RunnerPath != p.KitDirectory+"\\Invoke-SafeDemo.ps1") throw new ConnectionException("execution_invalid");
        var scenario=facts.ReadImmutable(p.ScenarioPath); var profile=facts.ReadImmutable(p.ProfilePath);
        var runner=facts.ReadImmutable(p.RunnerPath); var kit=facts.ReadImmutable(p.KitDirectory+"\\kit.json");
        var study=facts.ReadImmutable(p.StudyPath);
        var payload=facts.ReadImmutable(p.KitDirectory+"\\lab_update.ps1");
        if (!payload.SequenceEqual(Payload) || !facts.ReadImmutable(p.KitDirectory+"\\maintenance_check.ps1").SequenceEqual(Payload)) throw new ConnectionException("execution_invalid");
        var baseline=facts.ReadImmutable(p.KitDirectory+"\\baseline.xml"); var behavioral=facts.ReadImmutable(p.KitDirectory+"\\behavioral.xml");
        var actual=new ArtifactPins(ExecutionProfile.Hash(scenario),ExecutionProfile.Hash(profile),ExecutionProfile.Hash(runner),ExecutionProfile.Hash(kit),ExecutionProfile.Hash(payload));
        var rules=new RulePins(ExecutionProfile.Hash(baseline),ExecutionProfile.Hash(behavioral));
        var artifactHash=ExecutionProfile.Hash(ExecutionProtocol.CanonicalBytes(new { ArtifactPins=actual,RulePins=rules }));
        if (actual.ScenarioSha256 != ReviewedScenarioSha256 || actual != p.ArtifactPins || rules != p.RulePins || artifactHash != grant.Installed.ArtifactSetSha256 || ExecutionProfile.Hash(study)!=p.StudySha256)
            throw new ConnectionException("execution_invalid");
        VerifyStudy(grant,facts,study,kit,profile,scenario);
        return artifactHash;
    }

    private static JsonElement Document(byte[] bytes)
    {
        // Kit artifact_sha256 is a map, unlike execution protocol digest fields.
        // Apply bounded structural JSON rules without protocol-specific names.
        if(bytes.Length is <=0 or >65536)throw new JsonException();
        using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=12});
        void Unique(JsonElement value)
        {
            if(value.ValueKind==JsonValueKind.Object)
            {
                var names=new HashSet<string>(StringComparer.Ordinal);
                foreach(var property in value.EnumerateObject()) {if(!names.Add(property.Name))throw new JsonException();Unique(property.Value);}
            }
            else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);
            else if(value.ValueKind==JsonValueKind.Number && (!value.TryGetDouble(out var number) || !double.IsFinite(number)))throw new JsonException();
        }
        Unique(document.RootElement);
        return document.RootElement.Clone();
    }
    private static void Exact(JsonElement obj,params string[] keys)
    {
        if (obj.ValueKind!=JsonValueKind.Object || !obj.EnumerateObject().Select(p=>p.Name).Order().SequenceEqual(keys.Order())) throw new JsonException();
    }
    private static string S(JsonElement obj,string name) => obj.GetProperty(name).GetString() ?? throw new JsonException();
    private static void Equal(JsonElement obj,string name,string expected) { if (S(obj,name)!=expected) throw new JsonException(); }
    private static string Wire(string native) => JsonSerializer.Serialize(native,new JsonSerializerOptions { Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping })[1..^1];
    private static string[] Strings(JsonElement value) => value.EnumerateArray().Select(v=>v.GetString() ?? throw new JsonException()).ToArray();
    private static void VerifyStudy(ExecutionGrant grant,IExecutionFacts facts,byte[] studyBytes,byte[] kitBytes,byte[] profileBytes,byte[] scenarioBytes)
    {
        var p=grant.Profile;
        var study=Document(studyBytes);
        var kit=Document(kitBytes);
        Exact(study,"kind","version","study_id","pins","target","collection_reference","time_reference");
        Equal(study,"kind","scn001_study"); Equal(study,"version","0.1.0");
        foreach (var key in new[]{"study_id","collection_reference","time_reference"}) if(string.IsNullOrWhiteSpace(S(study,key))) throw new JsonException();
        var target=study.GetProperty("target");
        Exact(target,"environment_id","hostname","agent_id","account","elevated","executable","canonical_executable","collection_mode","native_directory","canonical_paths","command_lines","rule_id","parent_sid","field_profile");
        Equal(target,"environment_id",p.EnvironmentId); Equal(target,"hostname",p.ExpectedComputerName); Equal(target,"native_directory",p.KitDirectory);
        Equal(target,"collection_mode","direct"); Equal(target,"field_profile","wazuh-eventchannel-4.14.4-lf-v1");
        Equal(target,"executable",facts.PowerShellPath); Equal(target,"canonical_executable",Wire(facts.PowerShellPath));
        if(string.IsNullOrWhiteSpace(S(target,"agent_id")) || string.IsNullOrWhiteSpace(S(target,"account")) || target.GetProperty("elevated").ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new JsonException();
        var paths=Strings(target.GetProperty("canonical_paths")); var commands=Strings(target.GetProperty("command_lines"));
        if(!paths.SequenceEqual(new[]{Wire(p.KitDirectory+"\\lab_update.ps1"),Wire(p.KitDirectory+"\\maintenance_check.ps1")}) || commands.Length!=2 ||
            commands[0].Replace("lab_update.ps1","maintenance_check.ps1",StringComparison.Ordinal)!=commands[1] ||
            !commands.Select((v,i)=>v.Contains(paths[i],StringComparison.Ordinal)).All(v=>v)) throw new JsonException();
        var ruleId=target.GetProperty("rule_id").GetInt32(); var parent=target.GetProperty("parent_sid").GetInt32();
        if(ruleId is <100000 or >119999 || parent is <1 or >999999 || ruleId==parent) throw new JsonException();
        Exact(kit,"kind","kit_version","scenario_id","scenario_version","target_host","lab_directory","filenames","rule_id","parent_sid","field_profile","occupied_ids_declared","payload_sha256","artifact_sha256");
        Equal(kit,"kind","safe_demo_kit"); Equal(kit,"kit_version","0.3.0"); Equal(kit,"scenario_id","SCN-001"); Equal(kit,"scenario_version","0.1.0");
        Equal(kit,"target_host",p.ExpectedComputerName); Equal(kit,"lab_directory",p.KitDirectory); Equal(kit,"field_profile",S(target,"field_profile")); Equal(kit,"payload_sha256",p.ArtifactPins.PayloadSha256);
        if(kit.GetProperty("rule_id").GetInt32()!=ruleId || kit.GetProperty("parent_sid").GetInt32()!=parent || !Strings(kit.GetProperty("filenames")).SequenceEqual(new[]{"lab_update.ps1","maintenance_check.ps1"})) throw new JsonException();
        var occupied=kit.GetProperty("occupied_ids_declared").EnumerateArray().Select(v=>v.GetInt32()).ToArray();
        if(occupied.Distinct().Count()!=occupied.Length || occupied.Any(v=>v is <1 or >999999 || v==ruleId || v==ruleId+1)) throw new JsonException();
        var pins=study.GetProperty("pins"); Exact(pins,"scenario","profile","runner","kit","payload","baseline","fixed","behavioral");
        foreach(var (name,digest) in new[]{("scenario",p.ArtifactPins.ScenarioSha256),("profile",p.ArtifactPins.ProfileSha256),("runner",p.ArtifactPins.RunnerSha256),("kit",p.ArtifactPins.KitSha256),("payload",p.ArtifactPins.PayloadSha256),("baseline",p.RulePins.Baseline),("behavioral",p.RulePins.Behavioral)}) Equal(pins,name,digest);
        var cases=new[]{"comment-only","env-only","fragmented","marker-only","missing-counter","missing-text","original","pid-only","renamed","reworded","unrelated","wrong-channel","wrong-event-id","wrong-host","wrong-provider"};
        var names=new[]{"lab_update.ps1","maintenance_check.ps1","Invoke-SafeDemo.ps1","baseline.xml","fixed.xml","behavioral.xml","logtest-cases/catalog.json"}.Concat(cases.Select(n=>"logtest-cases/"+n+".synthetic.json")).ToArray();
        var artifacts=kit.GetProperty("artifact_sha256"); Exact(artifacts,names);
        foreach(var name in names)
        {
            var bytes=facts.ReadImmutable(p.KitDirectory+"\\"+name.Replace('/','\\'));
            if(ExecutionProfile.Hash(bytes)!=S(artifacts,name)) throw new JsonException();
            if(name=="fixed.xml") Equal(pins,"fixed",ExecutionProfile.Hash(bytes));
        }
        // Raw scenario bytes already match both the built-in reviewed hash and
        // grant. Existing Python verify_study validates YAML/fingerprint when
        // the per-device study is provisioned; no runtime YAML reinterpretation.
        VerifyProfile(Document(profileBytes),target,paths,commands,ruleId);
    }
    private static void VerifyProfile(JsonElement profile,JsonElement target,string[] paths,string[] commands,int ruleId)
    {
        Exact(profile,"profile_schema_version","profile_id","profile_version","scenario_id","scenario_version","scenario_fingerprint","rules");
        Equal(profile,"profile_schema_version","0.1.0"); Equal(profile,"scenario_id","SCN-001"); Equal(profile,"scenario_version","0.1.0");
        var rules=profile.GetProperty("rules").EnumerateArray().ToArray(); if(rules.Length!=3) throw new JsonException();
        object Predicate(string field,string op,string? value=null,string? binding=null,string[]? values=null) => new {field,op,value,binding,values};
        object[] Scope(string provider) => [Predicate("hostname","eq",binding:"target_host"),Predicate("asset_id","eq",binding:"target_agent"),Predicate("event_provider","eq",provider)];
        var path=Predicate("file_path","in",values:paths);
        var expected=new object[]{
            new {assertion_id="SCN-001-A01",role="telemetry",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-Sysmon"),match=new[]{Predicate("process_name","eq",S(target,"canonical_executable")),Predicate("command_line","in",values:commands)}},
            new {assertion_id="SCN-001-A02",role="telemetry",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-PowerShell"),match=new[]{path}},
            new {assertion_id="SCN-001-A03",role="detection",capability="supported",source_type="wazuh",scope=Scope("Microsoft-Windows-PowerShell"),match=new[]{path,Predicate("rule_id","exists"),Predicate("rule_id","eq",ruleId.ToString(CultureInfo.InvariantCulture))},
                correlation=new {anchor_assertion_id="SCN-001-A01",join_pairs=new[]{"hostname","asset_id","process_id"}.Select(k=>new {target_field=k,anchor_field=k}).ToArray(),min_delta_ns=-5000000000L,max_delta_ns=15000000000L}}};
        // Pydantic permits omitted defaults; remove only null defaults for comparison.
        JsonNode Normalize(JsonNode node)
        {
            if(node is JsonObject obj)
                foreach(var item in obj.ToArray()) { if(item.Value==null)obj.Remove(item.Key); else Normalize(item.Value); }
            else if(node is JsonArray array) foreach(var item in array) if(item!=null) Normalize(item);
            return node;
        }
        for(var i=0;i<3;i++)
        {
            var actual=Normalize(JsonNode.Parse(rules[i].GetRawText())!);
            var wanted=Normalize(JsonNode.Parse(ExecutionProtocol.CanonicalBytes(expected[i]))!);
            if(!JsonNode.DeepEquals(actual,wanted)) throw new JsonException();
        }
    }
}

internal sealed class NativeExecutionFacts : IExecutionFacts
{
    public bool Supported => OperatingSystem.IsWindowsVersionAtLeast(10) && RuntimeInformation.OSArchitecture==Architecture.X64 && Environment.Is64BitProcess;
    public string ExecutionBuildVersion => Protocol.AgentVersion;
    public string ComputerName => Environment.MachineName;
    public string PowerShellPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","WindowsPowerShell","v1.0","powershell.exe");
    public bool ServiceIdentity
    {
        get
        {
            if(!OperatingSystem.IsWindows())return false;
            using var current=WindowsIdentity.GetCurrent();
            try { var sid=(SecurityIdentifier)new NTAccount("NT SERVICE","AegisAgent").Translate(typeof(SecurityIdentifier)); return current.User==sid; }
            catch(IdentityNotMappedException){return false;}
        }
    }
    public byte[] ReadImmutable(string path) => ExecutionProfile.ReadImmutable(path);
    public void ValidateRunParent(string path)
    {
        ExecutionProfile.LocalPath(path,206); PrivatePaths.NoLinks(path);
        if(!Directory.Exists(path))throw new ConnectionException("execution_invalid");
        PrivatePaths.Verify(path,true);
        for(var p=new DirectoryInfo(path);p!=null;p=p.Parent) if(Directory.Exists(Path.Combine(p.FullName,".git")) || File.Exists(Path.Combine(p.FullName,".git")))throw new ConnectionException("execution_invalid");
    }
    // Task 4's contained native kernel must supply effective policy proof. No
    // uncontained helper, installer token, policy override or permissive fallback.
    public bool PolicyAllows(ExecutionGrant grant) => false;
    public bool TelemetryReadable()
    {
        if(!OperatingSystem.IsWindows() || !ServiceIdentity)return false;
        using(var engine=Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine",false))
            if(engine?.GetValue("PowerShellVersion") is not string version || !version.StartsWith("5.1.",StringComparison.Ordinal) || !File.Exists(PowerShellPath))return false;
        PrivatePaths.NoLinks(PowerShellPath);
        var manager=OpenSCManagerW(null,null,1); if(manager==0)return false;
        try
        {
            if(!(Running(manager,"Sysmon") || Running(manager,"Sysmon64")) || !Running(manager,"WazuhSvc"))return false;
            return ReadChannel("Microsoft-Windows-Sysmon/Operational",1) && ReadChannel("Microsoft-Windows-PowerShell/Operational",4104);
        }
        finally { CloseServiceHandle(manager); }
    }
    private static bool Running(nint manager,string name)
    {
        var service=OpenServiceW(manager,name,4); if(service==0)return false;
        try { return QueryServiceStatus(service,out var status) && status.CurrentState==4; }
        finally { CloseServiceHandle(service); }
    }
    private static bool ReadChannel(string channel,int eventId)
    {
        var config=EvtOpenChannelConfig(0,channel,0); if(config==0)return false;
        try
        {
            var buffer=Marshal.AllocHGlobal(32);
            try { if(!EvtGetChannelConfigProperty(config,0,0,32,buffer,out _) || Marshal.ReadInt32(buffer,8)!=13 || Marshal.ReadInt32(buffer)==0)return false; }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { EvtClose(config); }
        var query=EvtQuery(0,channel,$"*[System[(EventID={eventId})]]",0x201); if(query==0)return false;
        try
        {
            var handles=new nint[1];
            var success=EvtNext(query,1,handles,0,0,out var returned) && returned==1;
            foreach(var handle in handles)if(handle!=0)EvtClose(handle);
            return success;
        }
        finally { EvtClose(query); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint ServiceType,CurrentState,ControlsAccepted,Win32ExitCode,ServiceSpecificExitCode,CheckPoint,WaitHint; }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern nint OpenSCManagerW(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern nint OpenServiceW(nint manager,string name,uint access);
    [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool QueryServiceStatus(nint service,out ServiceStatus status);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CloseServiceHandle(nint handle);
    [DllImport("wevtapi.dll",CharSet=CharSet.Unicode)] private static extern nint EvtOpenChannelConfig(nint session,string channel,uint flags);
    [DllImport("wevtapi.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool EvtGetChannelConfigProperty(nint config,uint property,uint flags,uint size,nint buffer,out uint used);
    [DllImport("wevtapi.dll",CharSet=CharSet.Unicode)] private static extern nint EvtQuery(nint session,string path,string query,uint flags);
    [DllImport("wevtapi.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool EvtNext(nint result,uint size,[Out] nint[] events,uint timeout,uint flags,out uint returned);
    [DllImport("wevtapi.dll")] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool EvtClose(nint handle);
}
