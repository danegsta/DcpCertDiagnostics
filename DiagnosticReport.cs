using System.Text;

namespace DcpCertDiagnostic;

/// <summary>
/// Collects diagnostic data and formats it as a structured, human-readable report.
/// </summary>
internal sealed class DiagnosticReport
{
    private readonly StringBuilder _buffer = new();

    public void WriteHeader(string title)
    {
        var line = new string('=', 72);
        _buffer.AppendLine();
        _buffer.AppendLine(line);
        _buffer.AppendLine($"  {title}");
        _buffer.AppendLine(line);

        Console.WriteLine();
        WriteLineColor(line, ConsoleColor.Cyan);
        WriteLineColor($"  {title}", ConsoleColor.Cyan);
        WriteLineColor(line, ConsoleColor.Cyan);
    }

    public void WriteSubHeader(string title)
    {
        var line = new string('-', 48);
        _buffer.AppendLine();
        _buffer.AppendLine($"  --- {title} ---");

        Console.WriteLine();
        WriteLineColor($"  --- {title} ---", ConsoleColor.DarkCyan);
    }

    public void WriteField(string name, string value)
    {
        var formattedName = $"  {name,-45}";
        _buffer.AppendLine($"{formattedName}: {value}");
        Console.Write($"{formattedName}: ");
        Console.WriteLine(value);
    }

    public void WritePass(string message)
    {
        _buffer.AppendLine($"  [PASS] {message}");
        Console.Write("  ");
        WriteColor("[PASS] ", ConsoleColor.Green);
        Console.WriteLine(message);
    }

    public void WriteFail(string message)
    {
        _buffer.AppendLine($"  [FAIL] {message}");
        Console.Write("  ");
        WriteColor("[FAIL] ", ConsoleColor.Red);
        Console.WriteLine(message);
    }

    public void WriteWarn(string message)
    {
        _buffer.AppendLine($"  [WARN] {message}");
        Console.Write("  ");
        WriteColor("[WARN] ", ConsoleColor.Yellow);
        Console.WriteLine(message);
    }

    public void WriteInfo(string message)
    {
        _buffer.AppendLine($"  {message}");
        Console.Write("  ");
        Console.WriteLine(message);
    }

    public void WriteError(string message)
    {
        _buffer.AppendLine($"  {message}");
        Console.Write("  ");
        WriteLineColor(message, ConsoleColor.Red);
    }

    public void WriteLabel(string text)
    {
        _buffer.AppendLine();
        _buffer.AppendLine($"  {text}");
        Console.WriteLine();
        WriteLineColor($"  {text}", ConsoleColor.White);
    }

    public void WriteBlankLine()
    {
        _buffer.AppendLine();
        Console.WriteLine();
    }

    public void WriteRaw(string text)
    {
        _buffer.AppendLine(text);
        Console.WriteLine(text);
    }

    public void Flush(string? outputFilePath = null)
    {
        if (outputFilePath != null)
        {
            try
            {
                File.WriteAllText(outputFilePath, _buffer.ToString());
                Console.WriteLine();
                WriteLineColor($"Report written to: {outputFilePath}", ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                WriteLineColor($"Failed to write report file: {ex.Message}", ConsoleColor.Red);
            }
        }
    }

    public string GetReport() => _buffer.ToString();

    private static void WriteLineColor(string text, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.WriteLine(text);
            return;
        }
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ForegroundColor = prev;
    }

    private static void WriteColor(string text, ConsoleColor color)
    {
        if (Console.IsOutputRedirected)
        {
            Console.Write(text);
            return;
        }
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = prev;
    }
}
