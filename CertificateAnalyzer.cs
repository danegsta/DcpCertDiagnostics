using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace DcpCertDiagnostic;

/// <summary>
/// Performs low-level TLS/certificate analysis by connecting to the DCP server
/// via SslStream and examining the certificate chain.
/// </summary>
internal static class CertificateAnalyzer
{
    public static async Task AnalyzeAsync(KubeconfigData kubeconfig, DiagnosticReport report, CancellationToken cancellationToken)
    {
        report.WriteHeader("Certificate Chain Analysis (SslStream)");

        X509Certificate2? serverCert = null;
        X509Certificate2Collection? serverChain = null;

        // Connect via raw SslStream to capture the full certificate chain
        report.WriteInfo($"Connecting to {kubeconfig.Host}:{kubeconfig.Port} via SslStream...");

        try
        {
            using var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Parse(kubeconfig.Host), kubeconfig.Port, cancellationToken);
            report.WriteInfo("TCP connection established");

            RemoteCertificateValidationCallback validationCallback = (sender, certificate, chain, sslPolicyErrors) =>
            {
                // Capture the cert and chain for analysis, disposing any prior instances
                if (certificate is X509Certificate2 cert2)
                {
                    serverCert?.Dispose();
                    serverCert = new X509Certificate2(cert2);
                }
                else if (certificate != null)
                {
                    serverCert?.Dispose();
                    serverCert = new X509Certificate2(certificate);
                }

                if (chain != null)
                {
                    if (serverChain != null)
                    {
                        foreach (var oldCert in serverChain)
                        {
                            oldCert.Dispose();
                        }
                    }
                    serverChain = new X509Certificate2Collection();
                    foreach (var element in chain.ChainElements)
                    {
                        serverChain.Add(new X509Certificate2(element.Certificate));
                    }
                }

                report.WriteBlankLine();
                report.WriteSubHeader("SslStream Validation Callback");
                report.WriteInfo("Captures the SslPolicyErrors and chain status reported by .NET during TLS handshake.");
                report.WriteBlankLine();

                // Data fields
                report.WriteField("SslPolicyErrors", sslPolicyErrors.ToString());
                if (chain != null && chain.ChainStatus.Length > 0)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        report.WriteField("  Chain Status", $"{status.Status}: {status.StatusInformation}");
                    }
                }

                // Validation checks
                report.WriteLabel("Validation:");
                if (sslPolicyErrors == SslPolicyErrors.None)
                {
                    report.WritePass("No SSL policy errors reported by runtime");
                }
                else
                {
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
                    {
                        report.WriteFail("RemoteCertificateNotAvailable — server did not present a certificate");
                    }
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
                    {
                        report.WriteFail("RemoteCertificateNameMismatch — server name does not match certificate");
                    }
                    if (sslPolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                    {
                        // This is expected — DCP's CA is self-signed and ephemeral, never in the system trust store.
                        // KubernetesClient handles this by rebuilding the chain with CustomRootTrust.
                        if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                        {
                            report.WritePass("RemoteCertificateChainErrors (expected — DCP CA is not in system trust store)");
                        }
                        else
                        {
                            report.WriteFail("RemoteCertificateChainErrors — combined with other errors");
                        }
                    }
                }

                // Accept the cert for diagnostic purposes
                return true;
            };

            // Log the exact targetHost value — critical for diagnosing NameMismatch.
            // SChannel matches this against the cert's SANs; format differences
            // (e.g., [::1] vs ::1 vs 0:0:0:0:0:0:0:1) can cause mismatches on hardened machines.
            report.WriteBlankLine();
            report.WriteSubHeader("SslStream Target Host");
            report.WriteField("TargetHost Value", $"'{kubeconfig.Host}'");
            if (IPAddress.TryParse(kubeconfig.Host, out var targetIp))
            {
                report.WriteField("TargetHost Type", $"IP Address ({targetIp.AddressFamily})");
                report.WriteField("TargetHost Normalized", targetIp.ToString());
            }
            else
            {
                report.WriteField("TargetHost Type", "Hostname (DNS)");
            }

            using var sslStream = new SslStream(
                tcpClient.GetStream(),
                leaveInnerStreamOpen: false,
                userCertificateValidationCallback: validationCallback);

            var sslOptions = new SslClientAuthenticationOptions
            {
                TargetHost = kubeconfig.Host,
                RemoteCertificateValidationCallback = validationCallback,
            };

            await sslStream.AuthenticateAsClientAsync(sslOptions, cancellationToken);

            report.WriteBlankLine();
            report.WriteSubHeader("TLS Handshake Result");
            report.WriteInfo("Details of the negotiated TLS connection between this process and DCP.");
            report.WriteBlankLine();
            report.WriteField("TLS Protocol", sslStream.SslProtocol.ToString());
            report.WriteField("Negotiated Cipher Suite", sslStream.NegotiatedCipherSuite.ToString());
            report.WriteField("Is Authenticated", sslStream.IsAuthenticated.ToString());
            report.WriteField("Is Encrypted", sslStream.IsEncrypted.ToString());
            report.WriteField("Is Signed", sslStream.IsSigned.ToString());
            report.WriteField("Negotiated Application Protocol", sslStream.NegotiatedApplicationProtocol.ToString());

            report.WriteLabel("Validation:");
            report.WritePass($"TLS handshake completed (Protocol: {sslStream.SslProtocol}, CipherSuite: {sslStream.NegotiatedCipherSuite})");
        }
        catch (Exception ex)
        {
            report.WriteError($"SslStream connection failed: {ex.Message}");
            if (ex.InnerException != null)
            {
                report.WriteField("Inner Exception", ex.InnerException.Message);
                if (ex.InnerException.InnerException != null)
                {
                    report.WriteField("Inner Inner Exception", ex.InnerException.InnerException.Message);
                }
            }
            return;
        }

        // Analyze the server certificate
        if (serverCert == null)
        {
            report.WriteError("Server certificate was not captured during TLS handshake");
            return;
        }

        try
        {
            KubeconfigParser.DiagnoseCertificate(serverCert, "Server Certificate", report);

            // Analyze the chain presented by the server (skip [0] which is the server cert already printed above)
            if (serverChain != null && serverChain.Count > 1)
            {
                report.WriteBlankLine();
                report.WriteSubHeader("Additional Certificates in Server Chain");
                report.WriteField("Chain Length", serverChain.Count.ToString());

                for (int i = 1; i < serverChain.Count; i++)
                {
                    KubeconfigParser.DiagnoseCertificate(serverChain[i], $"Chain[{i}]", report);
                }
            }

            // Compare server-presented CA with kubeconfig CA
            CompareServerCaWithKubeconfigCa(serverCert, serverChain, kubeconfig, report);
            // X509Chain building with different policies
            await Task.Run(() => AnalyzeChainBuilding(serverCert, kubeconfig, report), cancellationToken);
        }
        finally
        {
            serverCert.Dispose();
            if (serverChain != null)
            {
                foreach (var cert in serverChain)
                {
                    cert.Dispose();
                }
            }
        }
    }

    private static void CompareServerCaWithKubeconfigCa(
        X509Certificate2 serverCert,
        X509Certificate2Collection? serverChain,
        KubeconfigData kubeconfig,
        DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("CA Certificate Comparison");
        report.WriteInfo("Checks that the CA in the TLS server chain is the same CA embedded in the kubeconfig.");
        report.WriteBlankLine();

        // Find CA cert in server chain
        X509Certificate2? serverCaCert = null;
        if (serverChain != null)
        {
            foreach (var cert in serverChain)
            {
                var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
                if (bc is { CertificateAuthority: true })
                {
                    serverCaCert = cert;
                    break;
                }
            }
        }

        if (serverCaCert == null)
        {
            report.WriteLabel("Validation:");
            report.WriteWarn("No CA certificate found in server-presented chain");
            report.WriteInfo("The server may not be sending the full chain (self-signed server cert)");

            if (serverCert.Subject == serverCert.Issuer)
            {
                report.WriteInfo("Server certificate appears to be self-signed (Subject == Issuer)");
            }
        }
        else
        {
            var serverCaBytes = serverCaCert.RawData;
            var kubeconfigCaBytes = kubeconfig.CaCertificate.RawData;

            if (serverCaBytes.AsSpan().SequenceEqual(kubeconfigCaBytes))
            {
                report.WriteLabel("Validation:");
                report.WritePass("Server chain CA matches kubeconfig CA (byte-identical)");
            }
            else
            {
                report.WriteLabel("Validation:");
                report.WriteFail("Server chain CA does NOT match kubeconfig CA");
                report.WriteField("  Server CA Thumbprint", serverCaCert.Thumbprint);
                report.WriteField("  Kubeconfig CA Thumbprint", kubeconfig.CaCertificate.Thumbprint);
                report.WriteField("  Server CA Subject", serverCaCert.Subject);
                report.WriteField("  Kubeconfig CA Subject", kubeconfig.CaCertificate.Subject);
            }
        }

        if (serverCert.Issuer == kubeconfig.CaCertificate.Subject)
        {
            report.WritePass("Server cert Issuer matches kubeconfig CA Subject");
        }
        else
        {
            report.WriteFail($"Server cert Issuer '{serverCert.Issuer}' does NOT match kubeconfig CA Subject '{kubeconfig.CaCertificate.Subject}'");
        }
    }


    private static void AnalyzeChainBuilding(
        X509Certificate2 serverCert,
        KubeconfigData kubeconfig,
        DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("X509Chain Building (Custom Trust Only)");
        report.WriteInfo("DCP certificates are ephemeral and never added to the system trust store.");
        report.WriteInfo("Mirrors KubernetesClient CertificateValidationCallBack: Build(serverCert) && Build(caCert)");
        report.WriteBlankLine();
        RunKubernetesClientEquivalentValidation(serverCert, kubeconfig.CaCertificate, report);

        // SAN match probe — test whether the cert matches different hostname formats
        AnalyzeSanMatching(serverCert, kubeconfig, report);

        // Additional chain building modes to isolate the cause of failures
        AnalyzeChainBuildingFallbackModes(serverCert, kubeconfig.CaCertificate, report);
    }

    /// <summary>
    /// Mirrors the exact validation logic from KubernetesClient.CertificateValidationCallBack.
    /// </summary>
    private static void RunKubernetesClientEquivalentValidation(
        X509Certificate2 serverCert,
        X509Certificate2 caCert,
        DiagnosticReport report)
    {
        const string label = "K8sClient";

        // Step 1: Build chain for server cert
        bool isValid;
        X509ChainStatus[] step1Status;
        string step1Chain;
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(caCert);

            try
            {
                isValid = chain.Build(serverCert);
            }
            catch (Exception ex)
            {
                report.WriteError($"[{label}] Step 1 chain.Build(serverCert) threw: {ex.Message}");
                WriteChainBuildExceptionDetail(ex, chain, report, $"{label} Step1");
                return;
            }

            step1Status = chain.ChainStatus.ToArray();
            step1Chain = string.Join(" → ",
                Enumerable.Range(0, chain.ChainElements.Count)
                    .Select(i => chain.ChainElements[i].Certificate.Subject));

            WritePerElementChainStatus(chain, report, $"{label} Step1");
        }

        // Step 2: Build chain for each CA cert (KubernetesClient iterates all certs in the collection)
        bool isTrusted;
        X509ChainStatus[] step2Status;
        string step2Chain;
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(caCert);

            try
            {
                isTrusted = chain.Build(caCert);
            }
            catch (Exception ex)
            {
                report.WriteError($"[{label}] Step 2 chain.Build(caCert) threw: {ex.Message}");
                WriteChainBuildExceptionDetail(ex, chain, report, $"{label} Step2");
                return;
            }

            step2Status = chain.ChainStatus.ToArray();
            step2Chain = string.Join(" → ",
                Enumerable.Range(0, chain.ChainElements.Count)
                    .Select(i => chain.ChainElements[i].Certificate.Subject));

            WritePerElementChainStatus(chain, report, $"{label} Step2");
        }

        // --- Diagnostic data ---
        report.WriteField($"  [{label} Step1] Build(serverCert)", isValid.ToString());
        foreach (var status in step1Status)
        {
            report.WriteField($"    Chain Status", $"{status.Status}: {status.StatusInformation}");
        }
        report.WriteField($"    Chain", step1Chain);

        report.WriteField($"  [{label} Step2] Build(caCert)", isTrusted.ToString());
        foreach (var status in step2Status)
        {
            report.WriteField($"    Chain Status", $"{status.Status}: {status.StatusInformation}");
        }
        report.WriteField($"    Chain", step2Chain);

        // --- Validation: single combined verdict ---
        bool combinedResult = isValid && isTrusted;

        report.WriteLabel("Validation:");

        if (combinedResult)
        {
            report.WritePass($"[{label}] KubernetesClient would ACCEPT (isValid={isValid}, isTrusted={isTrusted})");
        }
        else
        {
            report.WriteFail($"[{label}] KubernetesClient would REJECT (isValid={isValid}, isTrusted={isTrusted})");
        }
    }

    /// <summary>
    /// Captures detailed exception information when X509Chain.Build() throws, including
    /// HResult, inner exception chain, and any partial chain state.
    /// </summary>
    private static void WriteChainBuildExceptionDetail(
        Exception ex, X509Chain chain, DiagnosticReport report, string label)
    {
        report.WriteField($"    [{label}] Exception Type", ex.GetType().FullName ?? ex.GetType().Name);
        report.WriteField($"    [{label}] HResult", $"0x{ex.HResult:X8} ({ex.HResult})");

        // Capture partial chain state — may be populated even after a throw
        if (chain.ChainStatus.Length > 0)
        {
            foreach (var status in chain.ChainStatus)
            {
                report.WriteField($"    [{label}] Post-throw Status", $"{status.Status}: {status.StatusInformation}");
            }
        }
        report.WriteField($"    [{label}] Chain Elements Built", chain.ChainElements.Count.ToString());

        // Inner exception chain — captures OS-level error details
        var inner = ex.InnerException;
        int depth = 0;
        while (inner != null && depth < 5)
        {
            report.WriteField($"    [{label}] InnerException[{depth}]",
                $"{inner.GetType().Name}: {inner.Message} (HResult: 0x{inner.HResult:X8})");
            inner = inner.InnerException;
            depth++;
        }
    }

    /// <summary>
    /// Reports chain status for each individual chain element, showing which specific
    /// certificate in the chain caused each status flag.
    /// </summary>
    private static void WritePerElementChainStatus(X509Chain chain, DiagnosticReport report, string label)
    {
        if (chain.ChainElements.Count == 0) return;

        bool hasAnyElementStatus = false;
        for (int i = 0; i < chain.ChainElements.Count; i++)
        {
            var element = chain.ChainElements[i];
            if (element.ChainElementStatus.Length > 0)
            {
                hasAnyElementStatus = true;
                foreach (var status in element.ChainElementStatus)
                {
                    report.WriteField($"    [{label}] Element[{i}] ({element.Certificate.Subject})",
                        $"{status.Status}: {status.StatusInformation}");
                }
            }
        }

        if (!hasAnyElementStatus)
        {
            report.WriteField($"    [{label}] Per-element Status", "(no per-element errors)");
        }
    }

    /// <summary>
    /// Tests hostname matching against the server certificate using multiple IPv6 format variants.
    /// Uses .NET's built-in MatchesHostname() which is platform-neutral, independent from
    /// SChannel's hostname validation. Differences between these results and the SslStream
    /// callback's NameMismatch flag indicate an OS-level SChannel issue.
    /// </summary>
    private static void AnalyzeSanMatching(
        X509Certificate2 serverCert,
        KubeconfigData kubeconfig,
        DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("SAN Hostname Match Probe");
        report.WriteInfo("Tests server cert against multiple hostname formats using .NET's MatchesHostname().");
        report.WriteInfo("Differences from SslStream's NameMismatch flag indicate OS-level SChannel behavior.");
        report.WriteBlankLine();

        // Build list of hostname variants to test
        var hostnameVariants = new List<(string name, string value)>
        {
            ("Kubeconfig Host (actual)", kubeconfig.Host),
        };

        if (IPAddress.TryParse(kubeconfig.Host, out var ip))
        {
            // Add format variants for IP addresses
            var normalized = ip.ToString();
            if (normalized != kubeconfig.Host)
            {
                hostnameVariants.Add(("Normalized IP", normalized));
            }

            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                hostnameVariants.Add(("Bracketed IPv6", $"[{ip}]"));
                hostnameVariants.Add(("Expanded IPv6", ExpandIPv6(ip)));

                // Also test IPv4-mapped form if applicable
                if (ip.IsIPv4MappedToIPv6)
                {
                    hostnameVariants.Add(("IPv4-mapped", ip.MapToIPv4().ToString()));
                }
            }
        }

        foreach (var (name, hostname) in hostnameVariants)
        {
            try
            {
                bool matches = serverCert.MatchesHostname(hostname, allowWildcards: false, allowCommonName: true);
                if (matches)
                {
                    report.WritePass($"{name}: '{hostname}' → MATCH");
                }
                else
                {
                    report.WriteFail($"{name}: '{hostname}' → NO MATCH");
                }
            }
            catch (Exception ex)
            {
                report.WriteField($"{name}: '{hostname}'", $"Error: {ex.Message}");
            }
        }
    }

    private static string ExpandIPv6(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        var groups = new string[8];
        for (int i = 0; i < 8; i++)
        {
            groups[i] = ((bytes[i * 2] << 8) | bytes[i * 2 + 1]).ToString("x4");
        }
        return string.Join(":", groups);
    }

    /// <summary>
    /// Tests chain building with alternative trust and revocation modes to isolate the cause
    /// of failures seen under CustomRootTrust. Comparing results across modes reveals whether
    /// the issue is specific to custom trust, revocation policy, or the chain engine itself.
    /// </summary>
    private static void AnalyzeChainBuildingFallbackModes(
        X509Certificate2 serverCert,
        X509Certificate2 caCert,
        DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader("Chain Building Fallback Modes");
        report.WriteInfo("Tests chain building with alternative trust/revocation modes to isolate failures.");
        report.WriteBlankLine();

        // Mode 1: System trust with NoCheck — if this also throws, the chain engine is broadly broken
        TryChainBuild(report, "SystemTrust+NoCheck", serverCert, chain =>
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;
        });

        // Mode 2: Custom trust with Offline revocation — tests if revocation policy enforcement causes the throw
        TryChainBuild(report, "CustomTrust+OfflineRevocation", serverCert, chain =>
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(caCert);
        });

        // Mode 3: Custom trust with VerificationFlags that ignore common enterprise policy issues
        TryChainBuild(report, "CustomTrust+AllowUnknownCA", serverCert, chain =>
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(caCert);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        });
    }

    private static void TryChainBuild(
        DiagnosticReport report,
        string modeName,
        X509Certificate2 cert,
        Action<X509Chain> configureChain)
    {
        using var chain = new X509Chain();
        configureChain(chain);

        try
        {
            bool result = chain.Build(cert);
            report.WriteField($"  [{modeName}] Build()", result.ToString());
            foreach (var status in chain.ChainStatus)
            {
                report.WriteField($"    Status", $"{status.Status}: {status.StatusInformation}");
            }
        }
        catch (Exception ex)
        {
            report.WriteField($"  [{modeName}] Build()", $"THREW: {ex.Message}");
            report.WriteField($"    HResult", $"0x{ex.HResult:X8}");
            report.WriteField($"    Elements Built", chain.ChainElements.Count.ToString());
        }
    }

}
