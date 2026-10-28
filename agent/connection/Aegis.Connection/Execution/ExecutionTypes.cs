using System.Collections.Immutable;

namespace Aegis.Connection.Execution;

public sealed record ArtifactPins(string ScenarioSha256, string ProfileSha256, string RunnerSha256, string KitSha256, string PayloadSha256);
public sealed record RulePins(string Baseline, string Behavioral);
public sealed record ExecutionParameters(string RunLabel, string RuleRevision, string RuleSha256);
public sealed record ExecutionEnvelope(string Protocol, string KeyId, string Payload, string Signature);
public sealed record SignedJob(string Protocol, string JobId, string RunId, string DeviceId,
    string CertificateSha256, string ApprovalId, string EnvironmentId, int Generation,
    string BindingId, int BindingRevision, long ReleaseId, string ApprovalSnapshotSha256,
    string ScenarioId, string RunnerId, string RunnerVersion, string ScenarioSha256,
    string ProfileSha256, string RunnerSha256, string KitSha256, string PayloadSha256,
    string NotBefore, string ExpiresAt, string CollectionStart, string CollectionEnd,
    int TimeoutSeconds, ExecutionParameters Parameters);
public sealed record InstallationProfile(int SchemaVersion, string ProviderId, string EnvironmentId,
    string ExpectedComputerName, string ScenarioPath, string ProfilePath, string RunnerPath,
    string KitDirectory, string RunDirectory, string StudyPath, string StudySha256,
    ArtifactPins ArtifactPins, RulePins RulePins, bool AllowRehearsal, int TimeoutSeconds);
public sealed record InstalledGrant(int SchemaVersion, string DeviceId, int Generation, string CertificateSha256,
    string BindingId, int BindingRevision, string InstallationProfileSha256, string ArtifactSetSha256);
// The public-key hash is provisioned independently from all wire responses/profile bytes.
public sealed record ExecutionGrant(InstallationProfile Profile, InstalledGrant Installed, IdentityState Identity, string PublicKeySha256);
public sealed class VerifiedExecutionJob
{
    private readonly byte[] envelopeBytes;
    private readonly byte[] payloadBytes;
    public byte[] EnvelopeBytes => (byte[])envelopeBytes.Clone();
    public byte[] PayloadBytes => (byte[])payloadBytes.Clone();
    public string JobSha256 { get; }
    public SignedJob Job { get; }
    internal VerifiedExecutionJob(byte[] envelope, byte[] payload, string digest, SignedJob job)
    { envelopeBytes = (byte[])envelope.Clone(); payloadBytes = (byte[])payload.Clone(); JobSha256 = digest; Job = job; }
}
public sealed record PollRequest(string Protocol, string DeviceId, int Generation, string BindingId, int BindingRevision);
public sealed record ReadinessRequest(string Protocol, string DeviceId, int Generation, string BindingId, int BindingRevision,
    string InstallationProfileSha256, string ArtifactSetSha256, bool Ready, ImmutableArray<string> BlockingCodes);
public sealed record StartRequest(string Protocol, string DeviceId, int Generation, string BindingId, int BindingRevision,
    string StartRequestId, string JobSha256);
public sealed record ExecutionReceipt(string Protocol, string DeviceId, int Generation, string BindingId, int BindingRevision,
    string ReceiptId, string JobId, string JobSha256, string State, string? StartedAt, string FinishedAt,
    int? ExitCode, bool CleanupSucceeded);
public sealed record ReadinessAcknowledgment(string Protocol, string ServerTime, bool Accepted);
public sealed record StartAcknowledgment(string Protocol, string JobId, string StartRequestId, string JobSha256, bool Authorized);
public sealed record ReceiptAcknowledgment(string Protocol, string JobId, string ReceiptId, string JobSha256, bool Accepted);
public sealed record LocalReadiness(bool Ready, ImmutableArray<string> BlockingCodes, string InstallationProfileSha256, string ArtifactSetSha256);
public sealed record ExecutionObservation(DateTimeOffset? StartedAt, DateTimeOffset FinishedAt, int? ExitCode, bool CleanupSucceeded);
