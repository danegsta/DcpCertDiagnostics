using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using k8s;

namespace DcpCertDiagnostic;

/// <summary>
/// Attempts to connect to DCP using the KubernetesClient library with detailed
/// certificate validation logging — the same client path that Aspire uses.
/// </summary>
internal static class KubernetesClientDiagnostic
{
    public static async Task DiagnoseAsync(
        KubeconfigData kubeconfig, string kubeconfigPath,
        string dcpPath, DcpTlsOptions? devCertTlsOptions,
        DiagnosticReport report, CancellationToken cancellationToken)
    {
        report.WriteHeader("KubernetesClient Connection Diagnostic");

        // Build configuration from kubeconfig
        KubernetesClientConfiguration config;
        try
        {
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(kubeconfigPath);
            report.WriteInfo("KubernetesClientConfiguration built from kubeconfig");
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to build KubernetesClientConfiguration: {ex.Message}");
            LogExceptionChain(ex, report);
            return;
        }

        // Log configuration details
        report.WriteBlankLine();
        report.WriteSubHeader("KubernetesClientConfiguration Properties");
        report.WriteInfo("Configuration state after KubernetesClient parses the kubeconfig.");
        report.WriteBlankLine();
        report.WriteField("Host", config.Host);
        report.WriteField("SkipTlsVerify", config.SkipTlsVerify.ToString());
        report.WriteField("AccessToken", string.IsNullOrEmpty(config.AccessToken) ? "(not set)" : $"(set, {config.AccessToken.Length} chars)");
        report.WriteField("ClientCertificateData", config.ClientCertificateData != null ? $"(set, {config.ClientCertificateData.Length} bytes)" : "(not set)");
        report.WriteField("ClientCertificateKeyData", config.ClientCertificateKeyData != null ? "(set)" : "(not set)");

        if (config.SslCaCerts != null)
        {
            report.WriteField("SslCaCerts Count", config.SslCaCerts.Count.ToString());
            foreach (var cert in config.SslCaCerts)
            {
                report.WriteField("  CA Cert Subject", cert.Subject);
                report.WriteField("  CA Cert Thumbprint", cert.Thumbprint);
            }

            report.WriteLabel("Validation:");
            report.WritePass($"SslCaCerts present ({config.SslCaCerts.Count} certificate(s))");
        }
        else
        {
            report.WriteWarn("SslCaCerts is null — no CA certificates loaded from kubeconfig");
        }

        // Test 1: Connection with custom validation callback (detailed logging)
        report.WriteBlankLine();
        report.WriteSubHeader("Test 1: KubernetesClient with Custom Validation Callback");
        report.WriteInfo("Connects using a custom ServerCertificateCustomValidationCallback to log certificate details.");
        report.WriteBlankLine();

        await TestWithCustomCallback(config, report, cancellationToken);

        // Test 2: Connection with default behavior (what Aspire does)
        report.WriteBlankLine();
        report.WriteSubHeader("Test 2: KubernetesClient with Default Behavior");
        report.WriteInfo("Connects exactly as Aspire does — no custom callback, relies on KubernetesClient's built-in validation.");
        report.WriteBlankLine();

        await TestWithDefaultBehavior(kubeconfigPath, report, cancellationToken);

        // Test 3: Connection with SkipTlsVerify (to confirm connectivity)
        report.WriteBlankLine();
        report.WriteSubHeader("Test 3: KubernetesClient with SkipTlsVerify=true (connectivity check)");
        report.WriteInfo("Bypasses certificate validation to confirm the API server is reachable.");
        report.WriteBlankLine();

        await TestWithSkipTlsVerify(kubeconfigPath, report, cancellationToken);

        // Test 4: Connection using the ASP.NET Core dev certificate through DCP's platform-specific TLS options
        await TestWithDevCertTlsOptions(dcpPath, devCertTlsOptions, report, cancellationToken);
    }

    private static async Task TestWithCustomCallback(
        KubernetesClientConfiguration config,
        DiagnosticReport report,
        CancellationToken cancellationToken)
    {
        var callbackInvoked = false;

        try
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) =>
                {
                    callbackInvoked = true;

                    report.WriteInfo("--- Validation Callback Invoked ---");

                    // Data fields
                    report.WriteField("SslPolicyErrors", sslPolicyErrors.ToString());
                    if (chain != null && chain.ChainStatus.Length > 0)
                    {
                        foreach (var status in chain.ChainStatus)
                        {
                            report.WriteField("  Chain Status", $"{status.Status}: {status.StatusInformation}");
                        }
                    }

                    // Validation
                    report.WriteLabel("Validation:");
                    if (sslPolicyErrors == SslPolicyErrors.None)
                    {
                        report.WritePass("Callback returning true (no errors)");
                        return true;
                    }

                    // Perform KubernetesClient-equivalent validation
                    if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) != 0
                        && config.SslCaCerts != null && config.SslCaCerts.Count > 0 && cert != null)
                    {
                        using var validationChain = new X509Chain();
                        validationChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        validationChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        foreach (var caCert in config.SslCaCerts)
                        {
                            validationChain.ChainPolicy.CustomTrustStore.Add(caCert);
                        }

                        var isValid = validationChain.Build(cert);

                        bool isTrusted = false;
                        foreach (var caCert in config.SslCaCerts)
                        {
                            using var caChain = new X509Chain();
                            caChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                            caChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                            caChain.ChainPolicy.CustomTrustStore.Add(caCert);
                            if (caChain.Build(caCert))
                            {
                                isTrusted = true;
                                break;
                            }
                        }

                        var result = isValid && isTrusted;
                        if (result)
                        {
                            report.WritePass($"Callback returning true (custom chain validation passed: isValid={isValid}, isTrusted={isTrusted})");
                        }
                        else
                        {
                            report.WriteFail($"Callback returning false (custom chain validation failed: isValid={isValid}, isTrusted={isTrusted})");
                        }
                        return result;
                    }

                    report.WriteFail($"Callback returning false (sslPolicyErrors={sslPolicyErrors}, no custom CA available)");
                    return false;
                },
            };

            using var httpClient = new HttpClient(handler)
            {
                BaseAddress = new Uri(config.Host),
                Timeout = TimeSpan.FromSeconds(10),
            };

            if (!string.IsNullOrEmpty(config.AccessToken))
            {
                httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", config.AccessToken);
            }

            var response = await httpClient.GetAsync("/api", cancellationToken);
            report.WritePass($"HTTP request completed: {(int)response.StatusCode} {response.ReasonPhrase}");

            if (!callbackInvoked)
            {
                report.WriteWarn("Custom validation callback was NOT invoked — this may indicate a handler issue");
            }
        }
        catch (Exception ex)
        {
            if (!callbackInvoked)
            {
                report.WriteWarn("Custom validation callback was NOT invoked before exception");
            }

            report.WriteFail($"Connection failed: {ex.GetType().Name}: {ex.Message}");
            LogExceptionChain(ex, report);
        }
    }

    private static async Task TestWithDefaultBehavior(
        string kubeconfigPath,
        DiagnosticReport report,
        CancellationToken cancellationToken)
    {
        try
        {
            var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(kubeconfigPath);
            using var client = new Kubernetes(config);

            var version = await client.Version.GetCodeAsync(cancellationToken);
            report.WriteField("Server Version", $"{version.Major}.{version.Minor}");
            report.WriteField("Git Version", version.GitVersion);
            report.WriteField("Platform", version.Platform);

            report.WriteLabel("Validation:");
            report.WritePass("Default KubernetesClient connection succeeded");
        }
        catch (Exception ex)
        {
            report.WriteFail($"Default KubernetesClient connection failed: {ex.GetType().Name}: {ex.Message}");
            LogExceptionChain(ex, report);
        }
    }

    private static async Task TestWithSkipTlsVerify(
        string kubeconfigPath,
        DiagnosticReport report,
        CancellationToken cancellationToken)
    {
        try
        {
            var config = KubernetesClientConfiguration.BuildConfigFromConfigFile(kubeconfigPath);
            config.SkipTlsVerify = true;
            using var client = new Kubernetes(config);

            var version = await client.Version.GetCodeAsync(cancellationToken);
            report.WriteField("Server Version", $"{version.Major}.{version.Minor}");

            report.WriteLabel("Validation:");
            report.WritePass($"SkipTlsVerify connection succeeded — connectivity is OK");
        }
        catch (Exception ex)
        {
            report.WriteFail($"Even SkipTlsVerify connection failed: {ex.GetType().Name}: {ex.Message}");
            report.WriteError("This indicates a network/connectivity issue, not a TLS trust issue");
            LogExceptionChain(ex, report);
        }
    }

    /// <summary>
    /// Starts a second DCP instance with the ASP.NET dev cert and verifies
    /// KubernetesClient can connect. Windows uses thumbprint lookup; macOS/Linux
    /// use PEM certificate/key files.
    /// </summary>
    private static async Task TestWithDevCertTlsOptions(
        string dcpPath, DcpTlsOptions? tlsOptions,
        DiagnosticReport report, CancellationToken cancellationToken)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.Linux) &&
            !RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return;
        }

        report.WriteBlankLine();
        report.WriteSubHeader("Test 4: KubernetesClient with ASP.NET Core dev certificate");
        report.WriteInfo("Starts a second DCP instance using the ASP.NET Core dev certificate for TLS,");
        report.WriteInfo("then runs the same connection tests as above against that instance.");
        report.WriteBlankLine();

        if (tlsOptions == null)
        {
            report.WriteWarn("Skipped: No valid ASP.NET Core dev certificate was prepared for DCP TLS testing.");
            report.WriteInfo("Run 'dotnet dev-certs https --trust' to create and trust a dev certificate, then re-run.");
            return;
        }

        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && string.IsNullOrEmpty(tlsOptions.CertFile))
        {
            report.WriteWarn("Skipped: macOS/Linux DCP dev certificate testing requires PEM certificate and key files.");
            return;
        }

        if (!string.IsNullOrEmpty(tlsOptions.CertThumbprint))
        {
            report.WriteField("Dev Cert Thumbprint", tlsOptions.CertThumbprint);
        }

        await using var devCertDcp = new DcpProcessManager();
        var started = await devCertDcp.StartAsync(dcpPath, report, cancellationToken, tlsOptions, quiet: true);

        if (!started || devCertDcp.KubeconfigPath == null)
        {
            report.WriteFail("DCP failed to start with the ASP.NET Core dev certificate.");
            devCertDcp.DumpProcessOutput(report);
            return;
        }

        report.WriteInfo("DCP started with the ASP.NET Core dev certificate (PID captured, kubeconfig ready)");

        KubernetesClientConfiguration config;
        try
        {
            config = KubernetesClientConfiguration.BuildConfigFromConfigFile(devCertDcp.KubeconfigPath);
        }
        catch (Exception ex)
        {
            report.WriteFail($"Failed to build KubernetesClientConfiguration: {ex.Message}");
            devCertDcp.DumpProcessOutput(report);
            return;
        }

        report.WriteField("Host", config.Host);
        report.WriteField("SkipTlsVerify", config.SkipTlsVerify.ToString());
        if (config.SslCaCerts != null)
        {
            foreach (var cert in config.SslCaCerts)
            {
                report.WriteField("CA Cert Subject", cert.Subject);
                report.WriteField("CA Cert Thumbprint", cert.Thumbprint);
            }
        }

        // Run the same three test methods against the dev certificate DCP instance
        report.WriteBlankLine();
        report.WriteInfo("--- Test 4a: Custom Validation Callback ---");
        report.WriteBlankLine();
        await TestWithCustomCallback(config, report, cancellationToken);

        report.WriteBlankLine();
        report.WriteInfo("--- Test 4b: Default Behavior ---");
        report.WriteBlankLine();
        await TestWithDefaultBehavior(devCertDcp.KubeconfigPath, report, cancellationToken);

        report.WriteBlankLine();
        report.WriteInfo("--- Test 4c: SkipTlsVerify ---");
        report.WriteBlankLine();
        await TestWithSkipTlsVerify(devCertDcp.KubeconfigPath, report, cancellationToken);
    }

    private static void LogExceptionChain(Exception ex, DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("Exception Chain");

        var current = ex;
        int depth = 0;
        while (current != null && depth < 10)
        {
            var indent = new string(' ', depth * 2);
            report.WriteField($"{indent}[{depth}] Type", current.GetType().FullName ?? current.GetType().Name);
            report.WriteField($"{indent}[{depth}] Message", current.Message);
            report.WriteField($"{indent}[{depth}] Source", current.Source ?? "(null)");

            if (current is System.Net.Http.HttpRequestException httpEx)
            {
                report.WriteField($"{indent}[{depth}] StatusCode", httpEx.StatusCode?.ToString() ?? "(null)");
            }

            if (current is System.Security.Authentication.AuthenticationException)
            {
                report.WriteError($"{indent}[{depth}] This is an AuthenticationException — likely a TLS/certificate issue");
            }

            if (current.StackTrace != null)
            {
                // Only show first few frames
                var frames = current.StackTrace.Split('\n').Take(5);
                foreach (var frame in frames)
                {
                    report.WriteField($"{indent}[{depth}] Stack", frame.Trim());
                }
            }

            current = current.InnerException;
            depth++;
        }
    }
}
