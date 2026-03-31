using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;

namespace DcpCertDiagnostic;

/// <summary>
/// Manages the DCP process lifecycle: resolves the binary, starts the API server, and shuts it down.
/// </summary>
internal sealed class DcpProcessManager : IAsyncDisposable
{
    private Process? _dcpProcess;
    private string? _kubeconfigPath;
    private readonly ConcurrentQueue<string> _stdoutLines = new();
    private readonly ConcurrentQueue<string> _stderrLines = new();

    /// <summary>
    /// The path to the generated kubeconfig file.
    /// </summary>
    public string? KubeconfigPath => _kubeconfigPath;

    /// <summary>
    /// Resolves the DCP binary path. Uses the provided override path, or falls back to the
    /// path embedded in the assembly metadata from the Aspire.Hosting.Orchestration NuGet package.
    /// </summary>
    public static async Task<(string? Path, string? Version)> ResolveDcpPathAsync(string? overridePath, DiagnosticReport report)
    {
        report.WriteHeader("DCP Binary Resolution");

        if (!string.IsNullOrEmpty(overridePath))
        {
            report.WriteField("Source", "CLI argument override (--dcp-path)");
            report.WriteField("Path", overridePath);

            if (File.Exists(overridePath))
            {
                report.WriteInfo("DCP binary found at override path");
                var version = await LogBinaryInfoAsync(overridePath, report);
                return (overridePath, version);
            }
            else
            {
                report.WriteError($"DCP binary not found at override path: {overridePath}");
                return (null, null);
            }
        }

        // Try to resolve from assembly metadata (set by MSBuild target from NuGet package)
        report.WriteField("Source", "Assembly metadata (from Aspire.Hosting.Orchestration NuGet package)");

        var dcpCliPath = Assembly.GetExecutingAssembly()
            .GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == "DcpCliPath")
            ?.Value;

        if (string.IsNullOrEmpty(dcpCliPath))
        {
            report.WriteError("DcpCliPath assembly metadata not found");
            report.WriteInfo("This usually means the Aspire.Hosting.Orchestration NuGet package did not set $(DcpCliPath)");
            report.WriteInfo("Try using --dcp-path to specify the DCP binary path directly");
            return (null, null);
        }

        report.WriteField("Path (from metadata)", dcpCliPath);

        if (File.Exists(dcpCliPath))
        {
            report.WriteInfo("DCP binary found at NuGet package path");
            var version = await LogBinaryInfoAsync(dcpCliPath, report);
            return (dcpCliPath, version);
        }
        else
        {
            report.WriteError($"DCP binary not found at NuGet package path: {dcpCliPath}");
            report.WriteInfo("The NuGet package may not have been restored correctly, or the path may be stale");
            return (null, null);
        }
    }

    /// <summary>
    /// Starts DCP in API server-only mode and waits for the kubeconfig to be generated.
    /// When <paramref name="tlsCertThumbprint"/> is provided, DCP is started with
    /// <c>--tls-cert-thumbprint</c> so it uses the specified certificate from
    /// CurrentUser/My for TLS instead of generating an ephemeral one.
    /// </summary>
    public async Task<bool> StartAsync(string dcpPath, DiagnosticReport report, CancellationToken cancellationToken, string? tlsCertThumbprint = null)
    {
        report.WriteHeader(tlsCertThumbprint != null ? "DCP Process Startup (--tls-cert-thumbprint)" : "DCP Process Startup");

        // Create temp directory for kubeconfig
        var tempDir = Path.Combine(Path.GetTempPath(), $"dcp-cert-diag-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        _kubeconfigPath = Path.Combine(tempDir, "kubeconfig");

        report.WriteField("Kubeconfig Path", _kubeconfigPath);

        var arguments = $"start-apiserver --server-only --kubeconfig \"{_kubeconfigPath}\"";
        if (!string.IsNullOrEmpty(tlsCertThumbprint))
        {
            arguments += $" --tls-cert-thumbprint {tlsCertThumbprint}";
        }

        // Start DCP without DCP_SECURE_TOKEN so it generates a real bearer token
        // and writes it directly to the kubeconfig (matching non-Aspire usage).
        var startInfo = new ProcessStartInfo
        {
            FileName = dcpPath,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        report.WriteField("Command", $"{startInfo.FileName} {startInfo.Arguments}");
        report.WriteInfo("Starting DCP process...");

        try
        {
            _dcpProcess = Process.Start(startInfo);
            if (_dcpProcess == null)
            {
                report.WriteError("Process.Start returned null");
                return false;
            }

            report.WriteInfo($"DCP process started (PID: {_dcpProcess.Id})");

            // Capture stdout/stderr asynchronously (handlers run on thread pool)
            _dcpProcess.OutputDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    _stdoutLines.Enqueue(e.Data);
                }
            };
            _dcpProcess.ErrorDataReceived += (_, e) =>
            {
                if (e.Data != null)
                {
                    _stderrLines.Enqueue(e.Data);
                }
            };
            _dcpProcess.BeginOutputReadLine();
            _dcpProcess.BeginErrorReadLine();
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to start DCP: {ex.Message}");
            return false;
        }

        // Wait for kubeconfig to appear
        report.WriteInfo("Waiting for kubeconfig file to be generated...");

        var timeout = TimeSpan.FromSeconds(30);
        var stopwatch = Stopwatch.StartNew();

        while (stopwatch.Elapsed < timeout)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_dcpProcess.HasExited)
            {
                report.WriteError($"DCP process exited prematurely with code {_dcpProcess.ExitCode}");
                DumpProcessOutput(report);
                return false;
            }

            if (File.Exists(_kubeconfigPath))
            {
                try
                {
                    var content = File.ReadAllText(_kubeconfigPath);
                    if (content.Length > 0 && content.Contains("server:"))
                    {
                         report.WriteInfo($"Kubeconfig file generated ({content.Length} bytes, took {stopwatch.Elapsed.TotalSeconds:F1}s)");
                        return true;
                    }
                }
                catch (IOException)
                {
                    // File may still be being written
                }
            }

            await Task.Delay(200, cancellationToken);
        }

        report.WriteError($"Timed out waiting for kubeconfig after {timeout.TotalSeconds}s");
        DumpProcessOutput(report);
        return false;
    }

    /// <summary>
    /// Dumps captured DCP process output to the report.
    /// </summary>
    public void DumpProcessOutput(DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("DCP Process Output");

        var stdoutSnapshot = _stdoutLines.ToArray();
        if (stdoutSnapshot.Length > 0)
        {
            report.WriteInfo("--- stdout ---");
            foreach (var line in stdoutSnapshot.TakeLast(50))
            {
                report.WriteField("  stdout", line);
            }
        }
        else
        {
            report.WriteInfo("(no stdout captured)");
        }

        var stderrSnapshot = _stderrLines.ToArray();
        if (stderrSnapshot.Length > 0)
        {
            report.WriteInfo("--- stderr ---");
            foreach (var line in stderrSnapshot.TakeLast(50))
            {
                report.WriteField("  stderr", line);
            }
        }
        else
        {
            report.WriteInfo("(no stderr captured)");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_dcpProcess != null && !_dcpProcess.HasExited)
        {
            try
            {
                _dcpProcess.Kill(entireProcessTree: true);
                await _dcpProcess.WaitForExitAsync();
            }
            catch
            {
                // Best effort
            }
        }

        _dcpProcess?.Dispose();

        // Clean up temp kubeconfig
        if (_kubeconfigPath != null)
        {
            try
            {
                var dir = Path.GetDirectoryName(_kubeconfigPath);
                if (dir != null && Directory.Exists(dir))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
            catch
            {
                // Best effort
            }
        }
    }

    private static async Task<string?> LogBinaryInfoAsync(string path, DiagnosticReport report)
    {
        try
        {
            var fileInfo = new FileInfo(path);
            report.WriteField("File Size", $"{fileInfo.Length:N0} bytes");
            report.WriteField("Last Modified", fileInfo.LastWriteTimeUtc.ToString("O"));
        }
        catch
        {
            // Non-critical
        }

        // Try to get DCP version
        try
        {
            var versionInfo = new ProcessStartInfo
            {
                FileName = path,
                Arguments = "version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var process = Process.Start(versionInfo);
            if (process != null)
            {
                // Read stdout/stderr before WaitForExit to avoid deadlock
                var outputTask = process.StandardOutput.ReadToEndAsync();
                var errorTask = process.StandardError.ReadToEndAsync();
                if (process.WaitForExit(5000))
                {
                    var output = await outputTask;
                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        report.WriteField("DCP Version", output.Trim());
                        return output.Trim();
                    }
                }
                else
                {
                    try { process.Kill(); } catch { /* best effort */ }
                    report.WriteInfo("DCP version command timed out");
                }
            }
        }
        catch
        {
            report.WriteInfo("Could not determine DCP version");
        }

        return null;
    }
}
