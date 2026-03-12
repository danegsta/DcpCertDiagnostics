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
                return;
            }

            step1Status = chain.ChainStatus.ToArray();
            step1Chain = string.Join(" → ",
                Enumerable.Range(0, chain.ChainElements.Count)
                    .Select(i => chain.ChainElements[i].Certificate.Subject));
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
                return;
            }

            step2Status = chain.ChainStatus.ToArray();
            step2Chain = string.Join(" → ",
                Enumerable.Range(0, chain.ChainElements.Count)
                    .Select(i => chain.ChainElements[i].Certificate.Subject));
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

}
