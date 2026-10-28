namespace Aegis.Connection;

// The production runner shares this in-memory capability for the process lifetime.
// Restarting the process creates a fresh capability probe, without changing state.
internal sealed class NetworkHeartbeat
{
    internal static readonly NetworkHeartbeat Process = new();
    internal NetworkInventory Inventory { get; }
    private int unsupported;
    internal bool Unsupported => Volatile.Read(ref unsupported) != 0;
    internal NetworkHeartbeat(NetworkInventory? inventory = null) { Inventory = inventory ?? new NetworkInventory(); }
    internal void MarkUnsupported()
    {
        if (Interlocked.Exchange(ref unsupported, 1) == 0)
            Console.Error.WriteLine("{\"warning\":{\"code\":\"network_reporting_unsupported\"}}");
    }
}
