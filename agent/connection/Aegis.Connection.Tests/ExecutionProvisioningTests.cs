// Disposable-host TEST ASSEMBLY only. No production CLI exposes these entries.
using Aegis.Connection;
using Aegis.Connection.Execution;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Security.AccessControl;

internal static partial class Program
{
    private static void ExecutionProvisioningContracts()
    {
        Test("provisioning contract event descriptor matches manifest channel keyword",()=>{
            // Windows SDK mc.exe on our single-channel manifest emits exactly
            // {0x1,0x0,0x10,0x4,0x0,0x0,0x8000000000000000}.
            var descriptor=ProvisionFixtureEvent(1);
            Check(descriptor.Id==1 && descriptor.Version==0 && descriptor.Channel==16 && descriptor.Level==4 &&
                descriptor.Opcode==0 && descriptor.Task==0 && descriptor.Keyword==0x8000000000000000UL,"manifest descriptor mismatch");
        });
        if(!OperatingSystem.IsWindows())return;
        Test("provisioning contract immutable owner and object-specific permissions",()=>{
            if(!OperatingSystem.IsWindows())return;
            const string ti="S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
            DirectorySecurity Acl(string owner,string rules){if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();var acl=new DirectorySecurity();acl.SetSecurityDescriptorSddlForm("O:"+owner+"D:(A;;FA;;;SY)(A;;FA;;;BA)"+rules);return acl;}
            void Reject(DirectorySecurity acl,bool ancestor){if(!OperatingSystem.IsWindows())throw new PlatformNotSupportedException();try{ExecutionProfile.ValidateImmutableAcl(acl,ancestor);}catch(ConnectionException){return;}throw new Exception("unsafe ACL accepted");}
            ExecutionProfile.ValidateImmutableAcl(Acl("SY","(A;;FR;;;BU)"),false);
            ExecutionProfile.ValidateImmutableAcl(Acl(ti,"(A;;FA;;;"+ti+")"),true);
            Reject(Acl(ti,""),false);
            Reject(Acl("BU",""),true);
            foreach(var right in new[]{"GW","GA","0x10000","0x40","WD","WO"})
            {
                Reject(Acl("SY","(A;;"+right+";;;BU)"),false);
                Reject(Acl("SY","(A;;"+right+";;;BU)"),true);
            }
            ExecutionProfile.ValidateImmutableAcl(Acl("SY","(A;;0x6;;;BU)(A;OICIIO;GA;;;BU)"),true);
            ExecutionProfile.ValidateImmutableAcl(Acl("SY","(A;CI;0x116;;;BU)"),true);
            foreach(var right in new[]{"0x10","0x100","0x116"})Reject(Acl("SY","(A;;"+right+";;;BU)"),false);
            Reject(Acl("SY","(A;;0x6;;;BU)"),false);
            Reject(Acl("SY","(A;ID;GW;;;BU)"),false);
            Reject(Acl("SY","(A;;FA;;;"+ti+")"),false);
        });
        Test("provisioning contract OS ancestor classification is exact",()=>{
            if(!OperatingSystem.IsWindows())return;
            foreach(var folder in new[]{Environment.SpecialFolder.ProgramFiles,Environment.SpecialFolder.ProgramFilesX86,Environment.SpecialFolder.CommonApplicationData})
            {
                var known=Environment.GetFolderPath(folder);if(string.IsNullOrEmpty(known))continue;
                Check(ExecutionProfile.IsKnownOsAncestor(known) && ExecutionProfile.IsKnownOsAncestor(Path.GetPathRoot(known)!),"known OS ancestor rejected");
                Check(!ExecutionProfile.IsKnownOsAncestor(known+"-foreign") && !ExecutionProfile.IsKnownOsAncestor(Path.Combine(known,"untrusted")),"arbitrary path trusted");
            }
        });
        foreach(var folder in new[]{Environment.SpecialFolder.ProgramFiles,Environment.SpecialFolder.CommonApplicationData})
            Test("provisioning contract readonly actual OS ancestor "+folder,()=>{
                if(!OperatingSystem.IsWindows())return;
                var path=Environment.GetFolderPath(folder);
                ExecutionProfile.ValidateImmutableAcl(new DirectoryInfo(path).GetAccessControl(),ExecutionProfile.IsKnownOsAncestor(path));
                var root=Path.GetPathRoot(path)!;
                ExecutionProfile.ValidateImmutableAcl(new DirectoryInfo(root).GetAccessControl(),ExecutionProfile.IsKnownOsAncestor(root));
            });
    }
    private static FixtureEvent ProvisionFixtureEvent(ushort id)=>new(){Id=id,Channel=16,Level=4,Keyword=0x8000000000000000UL};
    private sealed record ProvisionInput(string Output, string ProgramFilesAsset, string ProgramDataAsset,
        string State, string FixtureService, string FixtureChannel, string DeniedChannel, string Mode,
        string User, string Password, string ZoneFile);
    private sealed class NativeCounts
    {
        public int executed { get; set; }
        public int passed { get; set; }
        public int failed { get; set; }
        public int skipped { get; set; }
    }
    private static int ProvisioningEntry(string[] args)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10) || !Environment.Is64BitProcess) return 3;
        try
        {
            if (args.Length == 2 && args[0] == "--provisioning-idle")
            {
                if(!System.Text.RegularExpressions.Regex.IsMatch(args[1],"^AegisFixture-[0-9a-f]{32}$"))return 3;
                return WindowsServiceHost.Run(Path.GetTempPath(), new FixtureServiceApi(args[1]), async (_, stop) =>
                { try { await Task.Delay(Timeout.Infinite, stop); } catch (OperationCanceledException) { } return 0; });
            }
            if (args.Length == 2 && args[0] == "--provisioning-service")
            {
                PrivatePaths.Verify(args[1],false);
                var input = JsonSerializer.Deserialize<ProvisionInput>(File.ReadAllBytes(args[1])) ?? throw new InvalidDataException();
                return WindowsServiceHost.Run(input.State, new FixtureServiceApi("AegisAgent"), (_, stop) => OperatingSystem.IsWindows() ? ProvisioningService(input, stop) : Task.FromResult(3));
            }
            if (args.Length == 3 && args[0] == "--provisioning-event")
            {
                if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
                var provider=Guid.Parse(args[1]);
                if(EventRegister(ref provider,0,0,out var handle)!=0)return 3;
                try { var descriptor=ProvisionFixtureEvent(ushort.Parse(args[2])); return EventWrite(handle,ref descriptor,0,0)==0 ? 0 : 3; }
                finally { EventUnregister(handle); }
            }
            if(args.Length==2 && args[0]=="--provisioning-journal")
            {
                if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
                var identity=StateStore.ReadExisting(args[1]);var (template,_)=PreflightFixture();
                using var certificate=X509Certificate2.CreateFromPem(identity.CertificatePem!);
                var profile=template.Profile with{EnvironmentId=identity.EnvironmentId!};
                var installed=template.Installed with{DeviceId=identity.DeviceId!,Generation=identity.Generation!.Value,
                    CertificateSha256=Convert.ToHexStringLower(SHA256.HashData(certificate.RawData)),
                    InstallationProfileSha256=Convert.ToHexStringLower(SHA256.HashData(ExecutionProtocol.CanonicalBytes(profile)))};
                var grant=template with{Profile=profile,Installed=installed,Identity=identity};
                var journal=new ExecutionJournal(Path.Combine(args[1],"execution"));
                for(var index=0;index<3;index++)
                {
                    var (job,_)=ExecutionFixture(grant);var entry=ExecutionJournalEntry.Received(job);journal.Transition(entry.JobId,null,entry);
                    if(index==0){var request=new StartRequest(ExecutionProtocol.Version,installed.DeviceId,installed.Generation,installed.BindingId,installed.BindingRevision,Guid.NewGuid().ToString(),job.JobSha256);journal.Transition(entry.JobId,"received",entry with{Phase="start_requested",StartRequest=Convert.ToBase64String(ExecutionProtocol.SerializeStart(request))});}
                    else {
                        var terminal=entry with{Phase="terminal",Receipt=Convert.ToBase64String(ExecutionCoordinator.Unknown(entry,DateTimeOffset.UtcNow))};journal.Transition(entry.JobId,"received",terminal);
                        if(index==2){var receipt=ExecutionProtocol.Decode<ExecutionReceipt>(ExecutionJournal.Raw(terminal.Receipt!));journal.Transition(entry.JobId,"terminal",terminal with{Phase="accepted",ReceiptAck=Convert.ToBase64String(ExecutionProtocol.CanonicalBytes(new ReceiptAcknowledgment(ExecutionProtocol.Version,entry.JobId,receipt.ReceiptId,entry.JobSha256,true)))});}
                    }
                }
                File.WriteAllText(Path.Combine(args[1],"execution",".journal-"+Guid.NewGuid().ToString("N")+".tmp"),"synthetic interrupted temporary");
                return 0;
            }
            if(args.Length==4 && args[0]=="--provisioning-config")
            {
                if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted")return 3;
                WriteProvisionConfiguration(args[1],args[2],args[3]);return 0;
            }
            return 2;
        }
        catch { Console.Error.WriteLine("native_fixture_failed"); return 3; }
    }
    private static void WriteProvisionConfiguration(string state,string assets,string runs)
    {
        // Generated TEST data only. Production receives its ordinary closed
        // contracts and immutable-file validation, with no test flag or shortcut.
        var identity=StateStore.ReadExisting(state);var (template,facts)=PreflightFixture();
        string PathMap(string value)=>value.Replace(@"C:\Reviewed",assets,StringComparison.Ordinal).Replace(@"C:\Runs",runs,StringComparison.Ordinal);
        string TextMap(string value)=>value.Replace(@"C:\\Reviewed",assets.Replace(@"\",@"\\"),StringComparison.Ordinal)
            .Replace(@"C:\Reviewed",assets,StringComparison.Ordinal).Replace("SYNTHETIC",identity.Hostname,StringComparison.Ordinal);
        JsonNode Rewrite(JsonNode node)
        {
            if(node is JsonObject obj){foreach(var key in obj.Select(p=>p.Key).ToArray())if(obj[key]!=null)obj[key]=Rewrite(obj[key]!.DeepClone());return obj;}
            if(node is JsonArray array){for(var i=0;i<array.Count;i++)if(array[i]!=null)array[i]=Rewrite(array[i]!.DeepClone());return array;}
            if(node is JsonValue value && value.TryGetValue<string>(out var text))return JsonValue.Create(TextMap(text))!;
            return node;
        }
        foreach(var (path,raw) in facts.Files)
        {
            var target=PathMap(path);Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            var bytes=path.EndsWith(".json",StringComparison.Ordinal) ? Encoding.UTF8.GetBytes(Rewrite(JsonNode.Parse(raw)!).ToJsonString()) : raw;
            File.WriteAllBytes(target,bytes);
        }
        var original=template.Profile;
        string Hash(string path)=>Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));
        var pins=new ArtifactPins(Hash(PathMap(original.ScenarioPath)),Hash(PathMap(original.ProfilePath)),Hash(PathMap(original.RunnerPath)),Hash(Path.Combine(PathMap(original.KitDirectory),"kit.json")),original.ArtifactPins.PayloadSha256);
        var studyPath=PathMap(original.StudyPath);var study=JsonNode.Parse(File.ReadAllBytes(studyPath))!;
        study["target"]!["environment_id"]=identity.EnvironmentId;
        study["pins"]!["profile"]=pins.ProfileSha256;study["pins"]!["kit"]=pins.KitSha256;
        File.WriteAllText(studyPath,study.ToJsonString());
        var profile=original with{EnvironmentId=identity.EnvironmentId!,ExpectedComputerName=identity.Hostname,
            ScenarioPath=PathMap(original.ScenarioPath),ProfilePath=PathMap(original.ProfilePath),RunnerPath=PathMap(original.RunnerPath),
            KitDirectory=PathMap(original.KitDirectory),RunDirectory=runs,StudyPath=studyPath,StudySha256=Hash(studyPath),ArtifactPins=pins};
        using var cert=X509Certificate2.CreateFromPem(identity.CertificatePem!);
        var installed=template.Installed with{DeviceId=identity.DeviceId!,Generation=identity.Generation!.Value,
            CertificateSha256=Convert.ToHexStringLower(SHA256.HashData(cert.RawData)),
            InstallationProfileSha256=Convert.ToHexStringLower(SHA256.HashData(ExecutionProtocol.CanonicalBytes(profile))),
            ArtifactSetSha256=Convert.ToHexStringLower(SHA256.HashData(ExecutionProtocol.CanonicalBytes(new{profile.ArtifactPins,profile.RulePins})))};
        File.WriteAllBytes(Path.Combine(assets,"profile.json"),ExecutionProtocol.CanonicalBytes(profile));
        File.WriteAllBytes(Path.Combine(assets,"installed-grant.json"),ExecutionProtocol.CanonicalBytes(installed));
        using var key=RSA.Create(3072);File.WriteAllText(Path.Combine(assets,"manager-execution-v2-public.pem"),key.ExportSubjectPublicKeyInfoPem());
    }
    [SupportedOSPlatform("windows")]
    private static async Task<int> ProvisioningService(ProvisionInput input, CancellationToken stop)
    {
        var counts=new Dictionary<string,NativeCounts>(); var failures=new List<string>();
        void Case(string category,string code,Action action)
        {
            if(!counts.TryGetValue(category,out var item))counts[category]=item=new();
            item.executed++;
            try{action();item.passed++;}catch{item.failed++;failures.Add(code);}
        }
        void Deny(Action action){try{action();}catch(UnauthorizedAccessException){return;}throw new InvalidOperationException();}
        Case("service_identity_acl","service_primary_identity",()=>{
            using var identity=WindowsIdentity.GetCurrent();
            var sid=(SecurityIdentifier)new NTAccount("NT SERVICE","AegisAgent").Translate(typeof(SecurityIdentifier));
            Check(identity.User==sid && new NativeExecutionFacts().ServiceIdentity,"primary identity");
            Check(identity.Groups != null && !identity.Groups.Any(g=>g.Value is "S-1-5-32-544" or "S-1-5-32-573"),"broad membership");
        });
        Case("service_identity_acl","state_write_and_immutable_denial",()=>{
            var file=Path.Combine(input.State,"service-write");File.WriteAllText(file,"synthetic");Check(File.ReadAllText(file)=="synthetic","state access");
            Deny(()=>{using var handle=File.Open(input.ProgramFilesAsset,FileMode.Open,FileAccess.Write,FileShare.Read);});
        });
        Case("service_identity_acl","ordinary_user_private_denial",()=>{
            Check(LogonUserW(input.User,".",input.Password,2,0,out var token),"test logon");
            using(token)WindowsIdentity.RunImpersonated(token,()=>{
                Deny(()=>File.ReadAllBytes(Path.Combine(input.State,"service-write")));
                Deny(()=>{using var handle=File.Open(input.ProgramDataAsset,FileMode.Open,FileAccess.Write,FileShare.Read);});
            });
        });
        if(input.Mode=="allowed")
        {
            Case("immutable_default_ancestors","program_files_immutable_loader",()=>Check(ExecutionProfile.ReadImmutable(input.ProgramFilesAsset).SequenceEqual("synthetic immutable"u8.ToArray()),"immutable loader"));
            Case("immutable_default_ancestors","program_data_immutable_loader",()=>Check(new NativeExecutionFacts().ReadImmutable(input.ProgramDataAsset).SequenceEqual("synthetic immutable"u8.ToArray()),"immutable loader"));
        }
        Case("service_channel_grants","effective_service_query",()=>Check(NativeExecutionFacts.ServiceRunning(input.FixtureService)==(input.Mode=="allowed"),"query access"));
        Case("service_channel_grants","effective_channel_read",()=>Check(NativeExecutionFacts.ReadChannel(input.FixtureChannel,1)==(input.Mode=="allowed"),"channel access"));
        Case("service_channel_grants","unrelated_channel_denied",()=>Check(!NativeExecutionFacts.ReadChannel(input.DeniedChannel,1),"unrelated access"));
        Case("service_channel_grants","source_mutation_rights_denied",()=>{
            var manager=FixtureOpenSCManagerW(null,null,1);Check(manager!=0,"SCM connect");
            try{foreach(uint access in new uint[]{2,0x10,0x20,0x40000}){var service=FixtureOpenServiceW(manager,input.FixtureService,access);if(service!=0){FixtureCloseServiceHandle(service);throw new InvalidOperationException();}}}
            finally{FixtureCloseServiceHandle(manager);}
        });
        Case("policy_denial","actual_origin_metadata_denial",()=>{
            Check(!ExecutionPowerShellPolicy.LocalOrigin(input.ZoneFile),"origin denied");
            Check(!ExecutionPowerShellPolicy.Allows(input.ZoneFile,ExecutionPowerShellPolicy.ReadEffectivePolicy,ExecutionPowerShellPolicy.LocalOrigin),"policy denied");
            Check(File.Exists(input.ZoneFile+":Zone.Identifier"),"origin retained");
        });
        Case("policy_denial","production_missing_vendor_refuses",()=>Check(!new NativeExecutionFacts().TelemetryReadable(),"vendor facts must fail on fixture-only host"));
        // A real contained tree remains active until the real SCM STOP reaches us.
        var marker=Path.Combine(input.State,"tree-marker-"+input.Mode);
        var native=WindowsExecutionNative.RunAsync(Environment.ProcessPath!,["--execution-child","tree",marker],
            input.State,TimeSpan.FromSeconds(45),_=>Task.CompletedTask,_=>{},stop);
        var ready=Stopwatch.StartNew();
        while(!File.Exists(marker+".grand") && !native.IsCompleted && ready.Elapsed<TimeSpan.FromSeconds(5))
            await Task.Delay(50,stop);
        Case("service_identity_acl","actual_scm_grandchild_started",()=>Check(File.Exists(marker+".grand"),"grandchild did not start"));
        WriteProvisionResult(input.Output,counts,failures,false);
        var result=await native;
        Case("service_identity_acl","actual_scm_stop_tree_cleanup",()=>Check(stop.IsCancellationRequested && result.Observation.CleanupSucceeded,"stop cleanup"));
        WriteProvisionResult(input.Output,counts,failures,true);
        return failures.Count==0 ? 0 : 3;
    }
    private static void WriteProvisionResult(string path,Dictionary<string,NativeCounts> counts,List<string> failures,bool complete)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new{schema_version=1,kind="execution_provisioning_service",complete,categories=counts,failures});
        using var stream=new FileStream(path,FileMode.Create,FileAccess.Write,FileShare.Read,4096,FileOptions.WriteThrough);stream.Write(bytes);stream.Flush(true);
    }
    [SupportedOSPlatform("windows")]
    private sealed class FixtureServiceApi(string name):IWindowsServiceApi
    {
        private FixtureMain? main;private FixtureControl? control;private nint handle;
        public bool Dispatch(Action callback){main=(_,_)=>callback();var entries=new[]{new FixtureServiceEntry{Name=name,Main=Marshal.GetFunctionPointerForDelegate(main)},default};var result=StartServiceCtrlDispatcherW(entries);GC.KeepAlive(main);GC.KeepAlive(control);return result;}
        public bool Register(Action<uint> callback){control=(code,_,_,_)=>{callback(code);return 0;};handle=RegisterServiceCtrlHandlerExW(name,control,0);return handle!=0;}
        public bool Report(ServiceStatus value){var status=new FixtureStatus{Type=0x10,State=(uint)value.State,Accepted=value.AcceptedControls,Win32=value.Win32ExitCode,Specific=value.ServiceExitCode,Checkpoint=value.Checkpoint,Wait=value.WaitHint};return SetServiceStatus(handle,ref status);}
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate void FixtureMain(uint count,nint argv);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate uint FixtureControl(uint control,uint type,nint data,nint context);
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]private struct FixtureServiceEntry{[MarshalAs(UnmanagedType.LPWStr)]public string? Name;public nint Main;}
    [StructLayout(LayoutKind.Sequential)]private struct FixtureStatus{public uint Type,State,Accepted,Win32,Specific,Checkpoint,Wait;}
    [StructLayout(LayoutKind.Sequential)]private struct FixtureEvent{public ushort Id;public byte Version,Channel,Level,Opcode;public ushort Task;public ulong Keyword;}
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool StartServiceCtrlDispatcherW([In]FixtureServiceEntry[] entries);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] private static extern nint RegisterServiceCtrlHandlerExW(string name,FixtureControl callback,nint context);
    [DllImport("advapi32.dll")] [return:MarshalAs(UnmanagedType.Bool)]private static extern bool SetServiceStatus(nint handle,ref FixtureStatus status);
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)]private static extern bool LogonUserW(string user,string domain,string password,int type,int provider,out SafeAccessTokenHandle token);
    [DllImport("advapi32.dll",EntryPoint="OpenSCManagerW",CharSet=CharSet.Unicode)]private static extern nint FixtureOpenSCManagerW(string? machine,string? database,uint access);
    [DllImport("advapi32.dll",EntryPoint="OpenServiceW",CharSet=CharSet.Unicode)]private static extern nint FixtureOpenServiceW(nint manager,string name,uint access);
    [DllImport("advapi32.dll",EntryPoint="CloseServiceHandle")] [return:MarshalAs(UnmanagedType.Bool)]private static extern bool FixtureCloseServiceHandle(nint handle);
    [DllImport("advapi32.dll")]private static extern uint EventRegister(ref Guid provider,nint callback,nint context,out long handle);
    [DllImport("advapi32.dll")]private static extern uint EventWrite(long handle,ref FixtureEvent descriptor,uint count,nint data);
    [DllImport("advapi32.dll")]private static extern uint EventUnregister(long handle);
}
