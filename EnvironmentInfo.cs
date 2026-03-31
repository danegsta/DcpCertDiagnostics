using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
            CollectWindowsCertificateChainPolicySettings(report);
            CollectWindowsIPv6Settings(report);
            CollectWindowsThirdPartyCertValidation(report);
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

    /// <summary>
    /// Collects Windows registry settings that affect certificate chain building, revocation
    /// checking, and root trust policy. These policies — often applied via Group Policy in
    /// hardened enterprise environments — can cause X509Chain.Build() to fail or throw for
    /// ephemeral self-signed certificates like those DCP generates.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CollectWindowsCertificateChainPolicySettings(DiagnosticReport report)
    {
        report.WriteSubHeader("Certificate Chain Policy (Windows)");
        report.WriteInfo("Group Policy and registry settings that affect certificate chain building and trust decisions.");
        report.WriteInfo("Enterprise hardening policies here can prevent custom trust of DCP's ephemeral CA.");
        report.WriteBlankLine();

        // Root auto-update policy — if disabled, chain building can fail for any CA not
        // manually installed, and also indicates a locked-down enterprise environment.
        ReadRegistryDword(report,
            @"SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot", "DisableRootAutoUpdate",
            Microsoft.Win32.RegistryHive.LocalMachine, "Root Auto-Update (Policy)");

        // Third-party root certificate auto-update flags
        ReadRegistryDword(report,
            @"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\AutoUpdate", "DisableRootAutoUpdate",
            Microsoft.Win32.RegistryHive.LocalMachine, "Root Auto-Update (System)");

        // Certificate revocation checking — policy-level enforcement
        // When enabled, forces CRL/OCSP checks that fail for ephemeral CAs with no revocation endpoints.
        ReadRegistryDword(report,
            @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "CertificateRevocation",
            Microsoft.Win32.RegistryHive.LocalMachine, "Revocation Checking (Policy)");

        ReadRegistryDword(report,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings", "CertificateRevocation",
            Microsoft.Win32.RegistryHive.CurrentUser, "Revocation Checking (User)");

        // SChannel-level settings that affect chain/certificate validation
        ReadRegistryDword(report,
            @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "CertificateMappingMethods",
            Microsoft.Win32.RegistryHive.LocalMachine, "SChannel CertificateMappingMethods");

        ReadRegistryDword(report,
            @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "EnableOcspStaplingForSni",
            Microsoft.Win32.RegistryHive.LocalMachine, "SChannel OCSP Stapling for SNI");

        // Issuer cache settings — small or disabled caches can affect chain building performance
        ReadRegistryDword(report,
            @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "IssuerCacheSize",
            Microsoft.Win32.RegistryHive.LocalMachine, "SChannel IssuerCacheSize");

        ReadRegistryDword(report,
            @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL", "IssuerCacheTime",
            Microsoft.Win32.RegistryHive.LocalMachine, "SChannel IssuerCacheTime");

        // Strong key protection — can force additional validation on certificate keys
        ReadRegistryDword(report,
            @"SOFTWARE\Policies\Microsoft\Cryptography", "ForceKeyProtection",
            Microsoft.Win32.RegistryHive.LocalMachine, "ForceKeyProtection (Policy)");

        // Cipher suite policy (Group Policy override) — just flag whether it's set,
        // don't dump the actual suite list (not privacy-sensitive, but very verbose).
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002");
            if (key != null)
            {
                var functions = key.GetValue("Functions");
                report.WriteField("Cipher Suite Policy (GPO)", functions != null ? "(custom cipher suite order set)" : "(not set)");
            }
            else
            {
                report.WriteField("Cipher Suite Policy (GPO)", "(not set — OS defaults)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("Cipher Suite Policy (GPO)", $"(unable to read: {ex.Message})");
        }

        // WinTrust Software Publishing state — controls certificate verification trust decisions
        ReadRegistryDword(report,
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing", "State",
            Microsoft.Win32.RegistryHive.CurrentUser, "WinTrust Software Publishing State");

        // 64-bit SchUseStrongCrypto (WOW6432Node) — may differ from the 32-bit value
        // already reported, which matters for cross-architecture processes.
        ReadRegistryDword(report,
            @"SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319", "SchUseStrongCrypto",
            Microsoft.Win32.RegistryHive.LocalMachine, "SchUseStrongCrypto (WOW64)");
    }

    /// <summary>
    /// Collects IPv6 configuration settings. DCP binds to [::1] (IPv6 loopback) and
    /// certificates use ::1 as an IP SAN. Partial IPv6 disablement or preference changes
    /// can affect how SChannel resolves and matches IPv6 addresses in certificate SANs.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CollectWindowsIPv6Settings(DiagnosticReport report)
    {
        report.WriteSubHeader("IPv6 Configuration");
        report.WriteInfo("DCP binds to [::1] (IPv6 loopback). IPv6 configuration can affect address resolution");
        report.WriteInfo("and how SChannel matches IPv6 addresses against certificate IP SANs.");
        report.WriteBlankLine();

        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters");
            if (key != null)
            {
                var disabledComponents = key.GetValue("DisabledComponents");
                if (disabledComponents is int value)
                {
                    report.WriteField("IPv6 DisabledComponents", $"0x{value:X2} ({value})");

                    // Decode the flags for readability
                    if (value == 0)
                    {
                        report.WriteInfo("  All IPv6 components enabled (default)");
                    }
                    else
                    {
                        if ((value & 0x01) != 0) report.WriteInfo("  Tunnel interfaces disabled");
                        if ((value & 0x10) != 0) report.WriteInfo("  Native IPv6 interfaces disabled");
                        if ((value & 0x20) != 0) report.WriteInfo("  IPv4 preferred over IPv6");
                        if (value == 0xFF) report.WriteInfo("  All IPv6 disabled except loopback");
                    }
                }
                else
                {
                    report.WriteField("IPv6 DisabledComponents", disabledComponents?.ToString() ?? "(not set — all enabled)");
                }
            }
            else
            {
                report.WriteField("IPv6 DisabledComponents", "(registry key not found — all enabled)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("IPv6 DisabledComponents", $"(unable to read: {ex.Message})");
        }

        // Check if IPv6 loopback is resolvable (functional check)
        try
        {
            var loopback = IPAddress.IPv6Loopback;
            report.WriteField("IPv6 Loopback Address", loopback.ToString());
            report.WriteField("IPv6 Loopback Available", Socket.OSSupportsIPv6.ToString());
        }
        catch (Exception ex)
        {
            report.WriteField("IPv6 Loopback Check", $"(error: {ex.Message})");
        }
    }

    /// <summary>
    /// Detects third-party software that can intercept or modify certificate validation.
    /// Enterprise endpoint protection (Zscaler, CrowdStrike, etc.) often hooks into CryptoAPI
    /// or SChannel via custom DLLs or GPO certificate policies. Only reports names and presence,
    /// not configuration values.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void CollectWindowsThirdPartyCertValidation(DiagnosticReport report)
    {
        report.WriteSubHeader("Third-Party Certificate Validation (Windows)");
        report.WriteInfo("Detects software that may intercept or modify certificate chain building.");
        report.WriteBlankLine();

        // Custom revocation providers — third-party DLLs registered for CRL/OCSP checking
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CertDllVerifyRevocation");
            if (key != null)
            {
                var subKeyNames = key.GetSubKeyNames();
                if (subKeyNames.Length > 0)
                {
                    report.WriteWarn($"Custom Revocation Providers: {subKeyNames.Length} registered");
                    foreach (var name in subKeyNames.Take(10))
                    {
                        report.WriteField("  Provider OID", name);
                    }
                }
                else
                {
                    report.WriteField("Custom Revocation Providers", "(none)");
                }
            }
            else
            {
                report.WriteField("Custom Revocation Providers", "(registry key not found)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("Custom Revocation Providers", $"(unable to read: {ex.Message})");
        }

        // GPO certificate policy stores — indicates enterprise certificate management
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Policies\Microsoft\SystemCertificates");
            if (key != null)
            {
                var subKeyNames = key.GetSubKeyNames();
                report.WriteField("GPO Certificate Stores", subKeyNames.Length > 0
                    ? string.Join(", ", subKeyNames)
                    : "(none)");
            }
            else
            {
                report.WriteField("GPO Certificate Stores", "(not configured)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("GPO Certificate Stores", $"(unable to read: {ex.Message})");
        }

        // Enterprise root certificate pinning (EKU restrictions)
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates");
            if (key != null)
            {
                var pinnedRoots = key.GetSubKeyNames();
                report.WriteField("GPO Pinned Root Certs", pinnedRoots.Length.ToString());
            }
            else
            {
                report.WriteField("GPO Pinned Root Certs", "(not configured)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField("GPO Pinned Root Certs", $"(unable to read: {ex.Message})");
        }

        // Custom authentication packages — third-party LSA plugins
        try
        {
            using var key = Microsoft.Win32.RegistryKey.OpenBaseKey(
                Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64)
                .OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            if (key != null)
            {
                var packages = key.GetValue("Authentication Packages") as string[];
                if (packages != null)
                {
                    // Only report non-default packages (msv1_0 is the Windows default)
                    var nonDefault = packages.Where(p => !string.Equals(p, "msv1_0", StringComparison.OrdinalIgnoreCase)).ToArray();
                    if (nonDefault.Length > 0)
                    {
                        report.WriteWarn($"Non-default Authentication Packages: {string.Join(", ", nonDefault)}");
                    }
                    else
                    {
                        report.WriteField("Authentication Packages", "(default only)");
                    }
                }
            }
        }
        catch (Exception ex)
        {
            report.WriteField("Authentication Packages", $"(unable to read: {ex.Message})");
        }
    }

    /// <summary>
    /// Reads a DWORD value from the Windows registry and writes it to the report.
    /// Only captures the numeric value — no private data.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void ReadRegistryDword(
        DiagnosticReport report,
        string subKeyPath,
        string valueName,
        Microsoft.Win32.RegistryHive hive,
        string displayName)
    {
        try
        {
            using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(hive, Microsoft.Win32.RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKeyPath);
            if (key != null)
            {
                var value = key.GetValue(valueName);
                report.WriteField(displayName, value?.ToString() ?? "(not set)");
            }
            else
            {
                report.WriteField(displayName, "(not set)");
            }
        }
        catch (Exception ex)
        {
            report.WriteField(displayName, $"(unable to read: {ex.Message})");
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
