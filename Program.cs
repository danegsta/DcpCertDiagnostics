namespace DcpCertDiagnostic;

/// <summary>
/// DCP Certificate Trust Diagnostic Tool
///
/// This tool starts a DCP instance, connects to it using the .NET KubernetesClient library,
/// and captures detailed certificate/TLS diagnostic information to help diagnose certificate
/// trust failures.
/// </summary>
internal static class Program
{
    static async Task<int> Main(string[] args)
    {
        string? dcpPathOverride = null;
        string? outputPath = null;

        // Parse simple CLI args
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--dcp-path" when i + 1 < args.Length:
                    dcpPathOverride = args[++i];
                    break;
                case "--output" or "-o" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
                case "--help" or "-h":
                    PrintUsage();
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown argument: {args[i]}");
                    PrintUsage();
                    return 1;
            }
        }

        // Default output path
        outputPath ??= Path.Combine(Directory.GetCurrentDirectory(), $"dcp-cert-diagnostic-{DateTime.UtcNow:yyyyMMdd-HHmmss}.txt");

        var report = new DiagnosticReport();

        report.WriteHeader("DCP Certificate Trust Diagnostic Tool");
        report.WriteField("Timestamp (UTC)", DateTime.UtcNow.ToString("O"));
        report.WriteField("Report Output Path", outputPath);
        report.WriteBlankLine();

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            // Phase 1: Environment information
            EnvironmentInfo.Collect(report);

            // Phase 2: Resolve DCP binary
            var dcpPath = await DcpProcessManager.ResolveDcpPathAsync(dcpPathOverride, report);
            if (dcpPath == null)
            {
                report.WriteBlankLine();
                report.WriteError("Cannot proceed without a DCP binary. Use --dcp-path to specify the path.");
                report.Flush(outputPath);
                return 1;
            }

            // Phase 3: Start DCP
            await using var dcpManager = new DcpProcessManager();
            var started = await dcpManager.StartAsync(dcpPath, report, cts.Token);
            if (!started || dcpManager.KubeconfigPath == null)
            {
                report.WriteBlankLine();
                report.WriteError("DCP failed to start. See above for details.");
                report.Flush(outputPath);
                return 1;
            }

            // Phase 4: Parse kubeconfig
            var kubeconfig = KubeconfigParser.ParseAndDiagnose(dcpManager.KubeconfigPath, report);
            if (kubeconfig == null)
            {
                report.WriteBlankLine();
                report.WriteError("Failed to parse kubeconfig. See above for details.");
                dcpManager.DumpProcessOutput(report);
                report.Flush(outputPath);
                return 1;
            }

            // Phase 5: Check proxy configuration for DCP server URL
            EnvironmentInfo.CheckProxyForTarget(kubeconfig.ServerUrl, report);

            // Phase 6: Certificate chain analysis (raw SslStream)
            await CertificateAnalyzer.AnalyzeAsync(kubeconfig, report, cts.Token);

            // Phase 7: KubernetesClient connection diagnostic
            await KubernetesClientDiagnostic.DiagnoseAsync(
                kubeconfig, dcpManager.KubeconfigPath, report, cts.Token);

            // Phase 8: Dump DCP process output for reference
            dcpManager.DumpProcessOutput(report);
        }
        catch (OperationCanceledException)
        {
            report.WriteBlankLine();
            report.WriteWarn("Diagnostic cancelled by user");
        }
        catch (Exception ex)
        {
            report.WriteBlankLine();
            report.WriteError($"Unexpected error: {ex}");
        }

        // Write summary
        report.WriteBlankLine();
        report.WriteHeader("Diagnostic Complete");
        report.WriteField("Report saved to", outputPath);
        report.WriteInfo("Please share the report file for analysis.");

        report.Flush(outputPath);
        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            DCP Certificate Trust Diagnostic Tool

            Usage: dotnet run [options]

            Options:
              --dcp-path <path>  Path to a custom DCP binary (overrides NuGet package)
              --output, -o <path>  Path for the diagnostic report output file
              --help, -h           Show this help message

            This tool starts a DCP instance, connects to it using the .NET KubernetesClient
            library, and captures detailed certificate and TLS diagnostic information.

            By default, the DCP binary is obtained from the Aspire.Hosting.Orchestration NuGet
            package (downloaded automatically on first build). Use --dcp-path to use a custom
            DCP binary instead.

            The diagnostic report is written to both the console and a timestamped file in the
            current directory. Share the file for analysis.
            """);
    }
}
