using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace Aegis.Connection;

public sealed record NetworkSnapshot(string CollectionStatus, string[]? ReportedIps, bool Truncated, string AgentVersion);
internal sealed record InterfaceAddresses(bool Up, IReadOnlyList<IPAddress> Addresses);

// OS enumeration is not cancellable on every platform. Retain the one outstanding
// read across deadlines; a later heartbeat discards its result before starting afresh.
public sealed class NetworkInventory
{
    private readonly object gate = new();
    private readonly Func<Task<NetworkSnapshot>> read;
    private readonly Func<TimeSpan, CancellationToken, Task> delay;
    private readonly TimeProvider clock;
    private Task<NetworkSnapshot>? outstanding;
    public NetworkInventory()
    {
        // Include normalization in the bounded work, not on the heartbeat thread.
        read = () => Task.Run(() => Normalize(ReadNative()));
        delay = Task.Delay; clock = TimeProvider.System;
    }
    internal NetworkInventory(Func<Task<IReadOnlyList<InterfaceAddresses>>> read, Func<TimeSpan, CancellationToken, Task> delay, TimeProvider clock)
    { this.read = async () => Normalize(await read().ConfigureAwait(false)); this.delay = delay; this.clock = clock; }
    private static NetworkSnapshot Unavailable() => new("unavailable", null, false, Protocol.AgentVersion);
    public async Task<NetworkSnapshot> CollectAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Task<NetworkSnapshot> task;
        long started;
        lock (gate)
        {
            if (outstanding != null && !outstanding.IsCompleted) return Unavailable();
            // Observe a late fault without ever publishing a late success.
            _ = outstanding?.Exception;
            started = clock.GetTimestamp();
            try { task = outstanding = read(); }
            catch (Exception) { return Unavailable(); }
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            var timeout = delay(TimeSpan.FromSeconds(2), deadline.Token);
            await Task.WhenAny(task, timeout);
            cancellationToken.ThrowIfCancellationRequested();
            if (timeout.IsCompleted || clock.GetElapsedTime(started) >= TimeSpan.FromSeconds(2)) return Unavailable();
            return await task;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return Unavailable(); }
        finally { deadline.Cancel(); }
    }
    private static IReadOnlyList<InterfaceAddresses> ReadNative() => NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up)
        .Select(n => new InterfaceAddresses(true, n.GetIPProperties().UnicastAddresses.Select(a => a.Address).ToArray())).ToArray();
    internal static NetworkSnapshot Normalize(IReadOnlyList<InterfaceAddresses> interfaces)
    {
        var addresses = new SortedSet<IPAddress>(Comparer<IPAddress>.Create((a, b) =>
        {
            var left = a.GetAddressBytes(); var right = b.GetAddressBytes();
            return left.Length != right.Length ? left.Length.CompareTo(right.Length) : left.AsSpan().SequenceCompareTo(right);
        }));
        foreach (var network in interfaces.Where(n => n.Up))
        foreach (var original in network.Addresses)
        {
            if (original.AddressFamily == AddressFamily.InterNetworkV6 && original.ScopeId != 0) continue;
            var address = original.IsIPv4MappedToIPv6 ? original.MapToIPv4() : original;
            var bytes = address.GetAddressBytes();
            if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) continue;
            if (address.AddressFamily == AddressFamily.InterNetwork && (bytes[0] is >= 224 and <= 239 || bytes[0] == 169 && bytes[1] == 254)) continue;
            if (address.AddressFamily == AddressFamily.InterNetworkV6 && (address.IsIPv6LinkLocal || address.IsIPv6Multicast)) continue;
            if (address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) addresses.Add(address);
        }
        return new("ok", addresses.Take(32).Select(a => a.ToString()).ToArray(), addresses.Count > 32, Protocol.AgentVersion);
    }
}
