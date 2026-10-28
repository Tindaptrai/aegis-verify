using System.Diagnostics;

namespace Aegis.Connection.Execution;

public readonly record struct ExecutionTimeBounds(DateTimeOffset EarliestUtc, DateTimeOffset LatestUtc);

// A deliberately conservative software bound, not a claim about oscillator accuracy.
public sealed class ExecutionClock
{
    private readonly object gate = new();
    private readonly Func<DateTimeOffset> utcNow;
    private readonly long origin = Stopwatch.GetTimestamp();
    private bool observed;
    private TimeSpan received, lastRead;
    private DateTimeOffset clientAtReceipt, lower, upper;
    private TimeSpan offsetBound, maxJump;
    public ExecutionClock() : this(() => DateTimeOffset.UtcNow) { }
    internal ExecutionClock(Func<DateTimeOffset> utcNow) { this.utcNow = utcNow; }
    public TimeSpan MonotonicNow => Stopwatch.GetElapsedTime(origin);

    // Call only for an authenticated, decoded server acknowledgment from this exchange.
    public void Observe(DateTimeOffset serverTime, DateTimeOffset sentUtc, TimeSpan sentMonotonic, TimeSpan receivedMonotonic)
    {
        lock (gate)
        {
            if (sentMonotonic < TimeSpan.Zero || receivedMonotonic < sentMonotonic ||
                observed && sentMonotonic < received || serverTime.Offset != TimeSpan.Zero || serverTime.Ticks % TimeSpan.TicksPerSecond != 0)
            { observed = false; return; }
            try
            {
                var roundTrip = receivedMonotonic - sentMonotonic;
                clientAtReceipt = sentUtc.ToUniversalTime() + roundTrip;
                lower = serverTime;
                upper = serverTime + TimeSpan.FromSeconds(1) + roundTrip;
                offsetBound = TimeSpan.FromTicks(Math.Max(Math.Abs((serverTime-clientAtReceipt).Ticks),
                    Math.Abs((serverTime+TimeSpan.FromSeconds(1)-sentUtc).Ticks)));
                received = lastRead = receivedMonotonic;
                maxJump = TimeSpan.Zero;
                observed = true;
            }
            catch (ArgumentOutOfRangeException) { observed = false; }
        }
    }
    public bool IsCertain(TimeSpan nowMonotonic) => TryGetBounds(nowMonotonic, out _);
    public bool TryGetBounds(TimeSpan nowMonotonic, out ExecutionTimeBounds bounds)
    {
        lock (gate)
        {
            bounds = default;
            if (!observed || nowMonotonic < received || nowMonotonic < lastRead) { observed = false; return false; }
            lastRead = nowMonotonic;
            try
            {
                var elapsed = nowMonotonic-received;
                var jump = (utcNow().ToUniversalTime() - (clientAtReceipt+elapsed)).Duration();
                if(jump>maxJump)maxJump=jump;
                var growth = elapsed+maxJump;
                if (elapsed > TimeSpan.FromSeconds(15) || offsetBound+growth > TimeSpan.FromSeconds(5)) return false;
                bounds = new(lower+elapsed-growth, upper+elapsed+growth);
                return true;
            }
            catch (ArgumentOutOfRangeException) { observed = false; return false; }
        }
    }
}
