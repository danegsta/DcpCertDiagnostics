using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DcpCertDiagnostic;

/// <summary>
/// Collects environment and runtime information relevant to TLS/certificate behavior.
/// </summary>
internal static class EnvironmentInfo
{
    public static void Collect(DiagnosticReport report)
    {
        report.WriteHeader("Environment Information");

        // OS info
        report.WriteField("OS Description", RuntimeInformation.OSDescription);
        report.WriteField("OS Architecture", RuntimeInformation.OSArchitecture.ToString());
        report.WriteField("Process Architecture", RuntimeInformation.ProcessArchitecture.ToString());
        report.WriteField("Runtime Identifier", RuntimeInformation.RuntimeIdentifier);

        // .NET runtime
        report.WriteField(".NET Runtime Version", RuntimeInformation.FrameworkDescription);
        report.WriteField("CLR Version", Environment.Version.ToString());

        // System clock
        report.WriteField("System UTC Time", DateTime.UtcNow.ToString("O"));
        report.WriteField("System Local Time", DateTime.Now.ToString("O"));
        report.WriteField("UTC Offset", TimeZoneInfo.Local.BaseUtcOffset.ToString());

        // TLS defaults
        try
        {
            report.WriteField("Default TLS Protocol", SslProtocols.None.ToString());
        }
        catch (Exception ex)
        {
            report.WriteField("TLS Default Check Error", ex.Message);
        }

        // Platform-specific TLS provider
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            CollectOpenSslInfo(report);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            CollectSChannelInfo(report);
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            CollectLinuxCryptoPolicy(report);
        }

        // Crypto settings
        CollectCryptoSettings(report);

        // Certificate trust store info
        CollectTrustStoreInfo(report);

        // Environment variables relevant to TLS/certificate behavior
        CollectTlsEnvironmentVariables(report);

        // Proxy configuration
        CollectProxyConfiguration(report);
    }

    /// <summary>
    /// Checks whether the DCP server URL would be routed through a proxy.
    /// Call after kubeconfig parsing when the server URL is known.
    /// </summary>
    public static void CheckProxyForTarget(string serverUrl, DiagnosticReport report)
    {
        report.WriteHeader("Proxy Detection for DCP Server");
        report.WriteInfo("Checks whether requests to the DCP API server URL would be routed through a proxy.");
        report.WriteInfo("A proxy intercepting loopback traffic can cause TLS trust failures via certificate re-signing.");
        report.WriteBlankLine();

        report.WriteField("Target URL", serverUrl);

        try
        {
            var targetUri = new Uri(serverUrl);
            report.WriteField("Target Host", targetUri.Host);
            report.WriteField("Target Port", targetUri.Port.ToString());

            var proxy = HttpClient.DefaultProxy;
            var proxyUri = proxy.GetProxy(targetUri);
            var isBypassed = proxy.IsBypassed(targetUri);

            report.WriteField("System Proxy for Target", proxyUri?.ToString() ?? "(none — direct connection)");
            report.WriteField("Proxy Bypassed", isBypassed.ToString());

            report.WriteLabel("Validation:");
            if (proxyUri != null && !isBypassed)
            {
                report.WriteWarn($"Target URL IS proxied via {proxyUri} — this proxy may intercept TLS and replace DCP's certificate");
            }
            else
            {
                report.WritePass("Target URL is NOT proxied — direct connection to DCP");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("Proxy Check Error", ex.Message);
        }
    }

    private static void CollectOpenSslInfo(DiagnosticReport report)
    {
        report.WriteSubHeader("OpenSSL / TLS Provider");

        try
        {
            var psi = new ProcessStartInfo("openssl", "version")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd().Trim();
                proc.StandardError.ReadToEnd();
                if (proc.WaitForExit(5000))
                {
                    report.WriteField("OpenSSL Version", output);
                }
                else
                {
                    try { proc.Kill(); } catch { /* best effort */ }
                }
            }
        }
        catch (Exception ex)
        {
            report.WriteField("OpenSSL Version", $"(unable to determine: {ex.Message})");
        }

        // Check for OpenSSL configuration
        try
        {
            var psi = new ProcessStartInfo("openssl", "version -d")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd().Trim();
                proc.StandardError.ReadToEnd();
                if (proc.WaitForExit(5000))
                {
                    report.WriteField("OpenSSL Config Dir", output);
                }
                else
                {
                    try { proc.Kill(); } catch { /* best effort */ }
                }
            }
        }
        catch
        {
            // Ignore — not critical
        }
    }

    private static void CollectSChannelInfo(DiagnosticReport report)
    {
        report.WriteSubHeader("SChannel / Windows TLS Provider");
        report.WriteField("Windows Version", Environment.OSVersion.ToString());
        report.WriteField("Is 64-bit OS", Environment.Is64BitOperatingSystem.ToString());

        // Check SChannel TLS protocol registry settings
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            CollectWindowsTlsRegistrySettings(report);
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CollectWindowsTlsRegistrySettings(DiagnosticReport report)
    {
        // Check for strong crypto enforcement
        try
        {
            using var netFxKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\.NETFramework\v4.0.30319");
            if (netFxKey != null)
            {
                var strongCrypto = netFxKey.GetValue("SchUseStrongCrypto");
                report.WriteField("SchUseStrongCrypto", strongCrypto?.ToString() ?? "(not set)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("SchUseStrongCrypto", $"(unable to read: {ex.Message})");
        }

        // Check FIPS policy
        try
        {
            using var fipsKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy");
            if (fipsKey != null)
            {
                var enabled = fipsKey.GetValue("Enabled");
                report.WriteField("FIPS Algorithm Policy", enabled?.ToString() == "1" ? "Enabled" : "Disabled");
            }
            else
            {
                report.WriteField("FIPS Algorithm Policy", "(registry key not found)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("FIPS Algorithm Policy", $"(unable to read: {ex.Message})");
        }

        // Check SChannel protocol settings
        var protocols = new[] { "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3" };
        foreach (var protocol in protocols)
        {
            try
            {
                using var clientKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    $@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{protocol}\Client");
                if (clientKey != null)
                {
                    var enabled = clientKey.GetValue("Enabled");
                    var disabledByDefault = clientKey.GetValue("DisabledByDefault");
                    report.WriteField($"SChannel {protocol} Client",
                        $"Enabled={enabled ?? "(not set)"}, DisabledByDefault={disabledByDefault ?? "(not set)"}");
                }
            }
            catch
            {
                // Registry key doesn't exist — OS defaults apply
            }
        }
    }

    private static void CollectTrustStoreInfo(DiagnosticReport report)
    {
        report.WriteSubHeader("Certificate Trust Store");

        // Try to open the system trust stores
        foreach (var storeName in new[] { StoreName.Root, StoreName.CertificateAuthority, StoreName.My })
        {
            foreach (var storeLocation in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
            {
                try
                {
                    using var store = new X509Store(storeName, storeLocation);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                    report.WriteField($"Store {storeLocation}/{storeName}", $"accessible, {store.Certificates.Count} certificates");
                }
                catch (Exception ex)
                {
                    report.WriteField($"Store {storeLocation}/{storeName}", $"NOT accessible: {ex.Message}");
                }
            }
        }
    }

    private static void CollectTlsEnvironmentVariables(DiagnosticReport report)
    {
        report.WriteSubHeader("TLS-Related Environment Variables");

        var envVars = new[]
        {
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "OPENSSL_CONF",
            "OPENSSL_FIPS",
            "CLR_OPENSSL_VERSION_OVERRIDE",
            "DOTNET_SYSTEM_NET_HTTP_USESOCKETSHTTPHANDLER",
            "DOTNET_SYSTEM_NET_SECURITY_TLSCIPHERSUITEPOLICY",
            "DOTNET_SYSTEM_NET_HTTP_SOCKETSHTTPHANDLER_HTTP2UNENCRYPTEDSUPPORT",
            "DOTNET_SYSTEM_NET_HTTP_SOCKETSHTTPHANDLER_HTTP3SUPPORT",
            "COMPlus_EnableDiagnostics",
            "COMPlus_FIPSMode",
            "ASPIRE_DCP_PATH",
            "ASPIRE_LAYOUT_PATH",
            "KUBECONFIG",
        };

        foreach (var envVar in envVars)
        {
            var value = Environment.GetEnvironmentVariable(envVar);
            report.WriteField(envVar, value ?? "(not set)");
        }
    }

    private static void CollectProxyConfiguration(DiagnosticReport report)
    {
        report.WriteSubHeader("Proxy Configuration");
        report.WriteInfo("Proxy servers that intercept HTTPS traffic can replace server certificates, causing TLS trust failures.");
        report.WriteBlankLine();

        // Proxy environment variables (both upper and lower case are significant)
        var proxyVars = new[]
        {
            "HTTP_PROXY", "http_proxy",
            "HTTPS_PROXY", "https_proxy",
            "NO_PROXY", "no_proxy",
            "ALL_PROXY", "all_proxy",
        };

        foreach (var envVar in proxyVars)
        {
            var value = Environment.GetEnvironmentVariable(envVar);
            if (value != null)
            {
                report.WriteField(envVar, value);
            }
        }

        // Check if any proxy vars are set at all
        var anyProxySet = proxyVars.Any(v => Environment.GetEnvironmentVariable(v) != null);
        if (!anyProxySet)
        {
            report.WriteField("Proxy Env Vars", "(none set)");
        }

        // .NET system proxy
        try
        {
            var proxy = HttpClient.DefaultProxy;
            // Test against common loopback addresses DCP uses
            foreach (var loopback in new[] { "https://127.0.0.1:443", "https://localhost:443" })
            {
                var uri = new Uri(loopback);
                var proxyUri = proxy.GetProxy(uri);
                var bypassed = proxy.IsBypassed(uri);
                if (proxyUri != null && !bypassed)
                {
                    report.WriteField($"System Proxy for {uri.Host}", proxyUri.ToString());
                }
            }
        }
        catch (Exception ex)
        {
            report.WriteField("System Proxy Check", $"(unable to determine: {ex.Message})");
        }
    }

    private static void CollectLinuxCryptoPolicy(DiagnosticReport report)
    {
        report.WriteSubHeader("System Crypto Policy");
        report.WriteInfo("RHEL/Fedora system-wide crypto policies can restrict allowed TLS versions and cipher suites.");
        report.WriteBlankLine();

        // Try update-crypto-policies --show (RHEL/Fedora)
        try
        {
            var psi = new ProcessStartInfo("update-crypto-policies", "--show")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                var output = proc.StandardOutput.ReadToEnd().Trim();
                proc.StandardError.ReadToEnd();
                if (proc.WaitForExit(5000))
                {
                    report.WriteField("Active Crypto Policy", output);
                }
                else
                {
                    try { proc.Kill(); } catch { /* best effort */ }
                }
            }
        }
        catch
        {
            // Not RHEL/Fedora — try reading the config file directly
            try
            {
                if (File.Exists("/etc/crypto-policies/config"))
                {
                    var policy = File.ReadAllText("/etc/crypto-policies/config").Trim();
                    report.WriteField("Active Crypto Policy", policy);
                }
                else
                {
                    report.WriteField("Active Crypto Policy", "(not applicable — no system crypto policy found)");
                }
            }
            catch (Exception ex)
            {
                report.WriteField("Active Crypto Policy", $"(unable to read: {ex.Message})");
            }
        }

        // Check for FIPS mode via /proc/sys/crypto/fips_enabled (Linux kernel)
        try
        {
            if (File.Exists("/proc/sys/crypto/fips_enabled"))
            {
                var fipsEnabled = File.ReadAllText("/proc/sys/crypto/fips_enabled").Trim();
                report.WriteField("Kernel FIPS Mode", fipsEnabled == "1" ? "Enabled" : "Disabled");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("Kernel FIPS Mode", $"(unable to read: {ex.Message})");
        }
    }

    private static void CollectCryptoSettings(DiagnosticReport report)
    {
        report.WriteSubHeader("Cryptography Settings");
        report.WriteInfo(".NET cryptographic provider configuration and FIPS compliance state.");
        report.WriteBlankLine();

        // .NET FIPS mode detection (CryptoConfig.AllowOnlyFipsAlgorithms is the documented API)
        try
        {
            #pragma warning disable SYSLIB0058 // CryptoConfig.AllowOnlyFipsAlgorithms is obsolete but still functional for detection
            report.WriteField(".NET AllowOnlyFipsAlgorithms", CryptoConfig.AllowOnlyFipsAlgorithms.ToString());
            #pragma warning restore SYSLIB0058
        }
        catch (Exception ex)
        {
            report.WriteField(".NET AllowOnlyFipsAlgorithms", $"(unable to determine: {ex.Message})");
        }

        // Detect the TLS provider .NET is actually using
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            report.WriteField(".NET TLS Provider", "OpenSSL (via platform interop)");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            report.WriteField(".NET TLS Provider", "Apple Security Framework");
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            report.WriteField(".NET TLS Provider", "SChannel");
        }
    }
}
