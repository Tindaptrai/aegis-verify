using System.Text;

namespace Aegis.Connection;

internal static class SecretPrompt
{
    internal static string Read()
    {
        if (Console.IsInputRedirected) return ReadRedirected();
        Console.Error.Write("Pairing code: "); var value = new StringBuilder(64);
        while (true)
        {
            var input = Console.ReadKey(intercept: true);
            if (input.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return value.ToString(); }
            if (input.Key == ConsoleKey.Escape || input.Key == ConsoleKey.C && input.Modifiers.HasFlag(ConsoleModifiers.Control)) throw new ConnectionException("prompt_cancelled");
            if (input.Key == ConsoleKey.Backspace) { if (value.Length > 0) value.Length--; continue; }
            if (char.IsControl(input.KeyChar) || value.Length >= 64) throw new ConnectionException("pairing_code_invalid");
            value.Append(input.KeyChar);
        }
    }
    private static string ReadRedirected()
    {
        var buffer = new char[64]; int length = 0;
        try
        {
            while (true)
            {
                var next = Console.In.Read();
                if (next == -1) break;
                if (next is '\r' or '\n')
                {
                    if (next == '\r' && Console.In.Read() != '\n') throw new ConnectionException("pairing_code_invalid");
                    if (Console.In.Read() != -1) throw new ConnectionException("pairing_code_invalid");
                    break;
                }
                if (length == buffer.Length || !(next is >= '0' and <= '9' or >= 'a' and <= 'f')) throw new ConnectionException("pairing_code_invalid");
                buffer[length++] = (char)next;
            }
            if (length != buffer.Length) throw new ConnectionException("pairing_code_invalid");
            return new string(buffer);
        }
        finally { Array.Clear(buffer); }
    }
}
