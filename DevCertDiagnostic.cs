using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace DcpCertDiagnostic;

/// <summary>
/// Checks for the ASP.NET Core HTTPS development certificate using
/// <c>dotnet dev-certs</c> metadata.
/// </summary>
internal static class DevCertDiagnostic
{
    /// <summary>
    /// Diagnoses ASP.NET Core dev certificates and prepares platform-appropriate
    /// DCP TLS options for dev certificate testing, if a current certificate exists.
    /// </summary>
    public static DcpTlsOptions? Diagnose(DiagnosticReport report)
    {
        report.WriteHeader("ASP.NET Core Development Certificate");

        var devCerts = GetDevCertMetadata(report);
        if (devCerts == null)
        {
            return null;
        }

        if (devCerts.Count == 0)
        {
            report.WriteInfo("No ASP.NET Core HTTPS development certificate found by 'dotnet dev-certs'.");
            report.WriteInfo("This is expected if you have not run 'dotnet dev-certs https' or are not using dev certs.");
            return null;
        }

        report.WriteField("Dev Certificates Found", devCerts.Count.ToString());
        report.WriteBlankLine();

        for (int i = 0; i < devCerts.Count; i++)
        {
            var cert = devCerts[i];
            if (devCerts.Count > 1)
            {
                report.WriteSubHeader($"Dev Certificate #{i + 1}");
            }

            ReportCertMetadata(cert, report);

            if (i < devCerts.Count - 1)
            {
                report.WriteBlankLine();
            }
        }

        var selectedCert = SelectDevCertificate(devCerts);
        if (selectedCert?.Thumbprint == null)
        {
            report.WriteBlankLine();
            report.WriteWarn("No current exportable ASP.NET Core dev certificate is available for DCP TLS testing.");
            return null;
        }

        if (devCerts.Count > 1)
        {
            report.WriteBlankLine();
            report.WriteField("Selected Dev Cert Thumbprint", selectedCert.Thumbprint);
            report.WriteField("Selected Trust Level", selectedCert.TrustLevel ?? "(not provided)");
        }

        return CreateDcpTlsOptions(selectedCert.Thumbprint, report);
    }

    private static DcpTlsOptions? CreateDcpTlsOptions(string certThumbprint, DiagnosticReport report)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return DcpTlsOptions.FromThumbprint(certThumbprint);
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return ExportDevCertificateFiles(certThumbprint);
        }

        report.WriteBlankLine();
        report.WriteSubHeader("DCP TLS Input for Dev Certificate");
        report.WriteWarn("Skipped: DCP dev certificate TLS testing is only configured for Windows, macOS, and Linux.");

        return null;
    }

    private static DcpTlsOptions? ExportDevCertificateFiles(string certThumbprint)
    {
        string? tempDir = null;

        try
        {
            tempDir = Path.Combine(Path.GetTempPath(), $"dcp-dev-cert-{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDir);
            RestrictUnixPermissions(
                tempDir,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        var certFile = Path.Combine(tempDir, "aspnet-dev-cert.pem");
        var keyFile = Path.ChangeExtension(certFile, ".key");

        if (!RunDotnetDevCertsPemExport(certFile))
        {
            CleanupTemporaryDirectory(tempDir);
            return null;
        }

        if (!File.Exists(certFile) || !File.Exists(keyFile))
        {
            CleanupTemporaryDirectory(tempDir);
            return null;
        }

        RestrictUnixPermissions(certFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        RestrictUnixPermissions(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        return DcpTlsOptions.FromCertificateFiles(
            certFile,
            keyFile,
            certThumbprint,
            temporaryDirectory: tempDir);
    }

    private static IReadOnlyList<DevCertMetadata>? GetDevCertMetadata(DiagnosticReport report)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("dev-certs");
        startInfo.ArgumentList.Add("https");
        startInfo.ArgumentList.Add("--check-trust-machine-readable");

        report.WriteField("Check Command", FormatCommandForDisplay(startInfo));

        try
        {
            using var process = Process.Start(startInfo);
            if (process == null)
            {
                report.WriteFail("Unable to start 'dotnet dev-certs' check process.");
                return null;
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(30_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Process exited after the timeout check.
                }

                report.WriteFail("'dotnet dev-certs' trust check timed out after 30 seconds.");
                return null;
            }

            var stdout = stdoutTask.GetAwaiter().GetResult().Trim();
            var stderr = stderrTask.GetAwaiter().GetResult().Trim();

            if (!string.IsNullOrWhiteSpace(stderr))
            {
                report.WriteField("dotnet dev-certs stderr", stderr);
            }

            if (string.IsNullOrWhiteSpace(stdout))
            {
                if (process.ExitCode != 0)
                {
                    report.WriteWarn($"'dotnet dev-certs' trust check exited with code {process.ExitCode} and no JSON output.");
                }

                return Array.Empty<DevCertMetadata>();
            }

            IReadOnlyList<DevCertMetadata>? certificates;
            try
            {
                certificates = JsonSerializer.Deserialize<List<DevCertMetadata>>(
                    stdout,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            }
            catch (JsonException ex)
            {
                report.WriteFail($"Unable to parse 'dotnet dev-certs' JSON output: {ex.Message}");
                report.WriteField("dotnet dev-certs stdout", stdout);
                return null;
            }

            if (process.ExitCode != 0)
            {
                report.WriteWarn($"'dotnet dev-certs' trust check exited with code {process.ExitCode}; using returned metadata for diagnostics.");
            }

            return certificates ?? Array.Empty<DevCertMetadata>();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            report.WriteFail($"Unable to run 'dotnet dev-certs' trust check: {ex.Message}");
            return null;
        }
    }

    private static void ReportCertMetadata(DevCertMetadata cert, DiagnosticReport report)
    {
        report.WriteField("Subject", cert.Subject ?? "(not provided)");
        report.WriteField("Thumbprint", cert.Thumbprint ?? "(not provided)");
        report.WriteField("Not Before (UTC)", FormatTimestamp(cert.ValidityNotBefore));
        report.WriteField("Not After (UTC)", FormatTimestamp(cert.ValidityNotAfter));
        report.WriteField("Dev Cert Version", cert.Version.ToString());
        report.WriteField("Is HTTPS Dev Cert", cert.IsHttpsDevelopmentCertificate.ToString());
        report.WriteField("Is Exportable", cert.IsExportable.ToString());
        report.WriteField("Trust Level", cert.TrustLevel ?? "(not provided)");

        if (cert.X509SubjectAlternativeNameExtension is { Count: > 0 } sanNames)
        {
            report.WriteField("SAN Names", string.Join(", ", sanNames));
        }

        report.WriteLabel("Validation:");

        if (cert.IsHttpsDevelopmentCertificate)
        {
            report.WritePass("Certificate is marked as an ASP.NET Core HTTPS development certificate");
        }
        else
        {
            report.WriteFail("Certificate is not marked as an ASP.NET Core HTTPS development certificate");
        }

        if (cert.IsExportable)
        {
            report.WritePass("Certificate is exportable");
        }
        else
        {
            report.WriteFail("Certificate is not exportable");
        }

        if (IsCurrent(cert))
        {
            report.WritePass("Certificate is currently valid");
        }
        else
        {
            report.WriteFail("Certificate is expired or not yet valid");
        }

        switch (TrustRank(cert.TrustLevel))
        {
            case 3:
                report.WritePass("Trust level is Full");
                break;
            case 2:
                report.WriteWarn("Trust level is Partial");
                break;
            case 1:
                report.WriteFail("Trust level is None");
                break;
            default:
                report.WriteWarn("Trust level is unknown");
                break;
        }
    }

    private static DevCertMetadata? SelectDevCertificate(IEnumerable<DevCertMetadata> devCerts)
    {
        return devCerts
            .Where(IsUsableForDcp)
            .OrderByDescending(cert => TrustRank(cert.TrustLevel))
            .ThenByDescending(cert => cert.Version)
            .ThenByDescending(cert => cert.ValidityNotAfter)
            .FirstOrDefault();
    }

    private static bool IsUsableForDcp(DevCertMetadata cert)
    {
        return cert.IsHttpsDevelopmentCertificate
            && cert.IsExportable
            && IsCurrent(cert)
            && !string.IsNullOrWhiteSpace(cert.Thumbprint);
    }

    private static bool IsCurrent(DevCertMetadata cert)
    {
        if (cert.ValidityNotBefore == default || cert.ValidityNotAfter == default)
        {
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        return now >= cert.ValidityNotBefore.ToUniversalTime()
            && now <= cert.ValidityNotAfter.ToUniversalTime();
    }

    private static int TrustRank(string? trustLevel)
    {
        if (string.Equals(trustLevel, "Full", StringComparison.OrdinalIgnoreCase))
        {
            return 3;
        }

        if (string.Equals(trustLevel, "Partial", StringComparison.OrdinalIgnoreCase))
        {
            return 2;
        }

        if (string.Equals(trustLevel, "None", StringComparison.OrdinalIgnoreCase))
        {
            return 1;
        }

        return 0;
    }

    private static string FormatTimestamp(DateTimeOffset timestamp)
    {
        return timestamp == default
            ? "(not provided)"
            : timestamp.ToUniversalTime().ToString("O");
    }

    private static bool RunDotnetDevCertsPemExport(string certFile)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "dotnet",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("dev-certs");
        startInfo.ArgumentList.Add("https");
        startInfo.ArgumentList.Add("--export-path");
        startInfo.ArgumentList.Add(certFile);
        startInfo.ArgumentList.Add("--format");
        startInfo.ArgumentList.Add("PEM");
        startInfo.ArgumentList.Add("--no-password");

        try
        {
            using var process = Process.Start(startInfo);
            if (process == null)
            {
                return false;
            }

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(30_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Process exited after the timeout check.
                }

                return false;
            }

            _ = stdoutTask.GetAwaiter().GetResult();
            _ = stderrTask.GetAwaiter().GetResult();

            return process.ExitCode == 0;
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static void RestrictUnixPermissions(string path, UnixFileMode mode)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(path, mode);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or PlatformNotSupportedException)
        {
        }
    }

    private static string FormatCommandForDisplay(ProcessStartInfo startInfo)
    {
        return string.Join(" ", new[] { startInfo.FileName }
            .Concat(startInfo.ArgumentList)
            .Select(QuoteArgumentForDisplay));
    }

    private static string QuoteArgumentForDisplay(string argument)
    {
        if (argument.Length == 0)
        {
            return "\"\"";
        }

        return argument.Any(char.IsWhiteSpace) || argument.Contains('"')
            ? $"\"{argument.Replace("\"", "\\\"")}\""
            : argument;
    }

    private static void CleanupTemporaryDirectory(string temporaryDirectory)
    {
        try
        {
            if (Directory.Exists(temporaryDirectory))
            {
                Directory.Delete(temporaryDirectory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed class DevCertMetadata
    {
        public string? Thumbprint { get; set; }

        public string? Subject { get; set; }

        public IReadOnlyList<string>? X509SubjectAlternativeNameExtension { get; set; }

        public int Version { get; set; }

        public DateTimeOffset ValidityNotBefore { get; set; }

        public DateTimeOffset ValidityNotAfter { get; set; }

        public bool IsHttpsDevelopmentCertificate { get; set; }

        public bool IsExportable { get; set; }

        public string? TrustLevel { get; set; }
    }

}
