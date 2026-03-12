using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using YamlDotNet.RepresentationModel;

namespace DcpCertDiagnostic;

/// <summary>
/// Parsed kubeconfig data extracted from the YAML file.
/// </summary>
internal sealed record KubeconfigData
{
    public required string ServerUrl { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required string Token { get; init; }
    public required byte[] CaCertBytes { get; init; }
    public required X509Certificate2 CaCertificate { get; init; }
    public required string RawYaml { get; init; }
}

/// <summary>
/// Parses a kubeconfig file and extracts certificate, server, and token data.
/// </summary>
internal static class KubeconfigParser
{
    public static KubeconfigData? ParseAndDiagnose(string kubeconfigPath, DiagnosticReport report)
    {
        report.WriteHeader("Kubeconfig Analysis");

        // Read the file
        report.WriteField("Kubeconfig Path", kubeconfigPath);

        string yaml;
        try
        {
            yaml = File.ReadAllText(kubeconfigPath);
            report.WriteField("Kubeconfig Size", $"{yaml.Length} bytes");
            report.WriteInfo("Kubeconfig file read successfully");
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to read kubeconfig: {ex.Message}");
            return null;
        }

        // Parse the YAML
        var yamlStream = new YamlStream();
        try
        {
            using var reader = new StringReader(yaml);
            yamlStream.Load(reader);
            report.WriteInfo("YAML parsed successfully");
        }
        catch (Exception ex)
        {
            report.WriteError($"YAML parse error: {ex.Message}");
            return null;
        }

        if (yamlStream.Documents.Count == 0)
        {
            report.WriteError("No YAML documents found in kubeconfig");
            return null;
        }

        var root = (YamlMappingNode)yamlStream.Documents[0].RootNode;

        // Extract server URL from clusters[0].cluster.server
        string? serverUrl = null;
        string? caData = null;
        string? token = null;

        try
        {
            var clusters = (YamlSequenceNode)root.Children[new YamlScalarNode("clusters")];
            var cluster = (YamlMappingNode)clusters[0];
            var clusterData = (YamlMappingNode)cluster.Children[new YamlScalarNode("cluster")];

            if (clusterData.Children.TryGetValue(new YamlScalarNode("server"), out var serverNode))
            {
                serverUrl = ((YamlScalarNode)serverNode).Value;
            }

            if (clusterData.Children.TryGetValue(new YamlScalarNode("certificate-authority-data"), out var caNode))
            {
                caData = ((YamlScalarNode)caNode).Value;
            }

            // Check for insecure-skip-tls-verify
            if (clusterData.Children.TryGetValue(new YamlScalarNode("insecure-skip-tls-verify"), out var insecureNode))
            {
                var insecureValue = ((YamlScalarNode)insecureNode).Value;
                report.WriteField("insecure-skip-tls-verify", insecureValue ?? "null");
                if (insecureValue?.ToLowerInvariant() == "true")
                {
                    report.WriteLabel("Validation:");
                    report.WriteWarn("insecure-skip-tls-verify is set to true — TLS verification is disabled");
                }
            }
            else
            {
                report.WriteField("insecure-skip-tls-verify", "(not set — TLS verification enabled)");
            }
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to extract cluster data: {ex.Message}");
            return null;
        }

        // Extract token from users[0].user.token
        try
        {
            var users = (YamlSequenceNode)root.Children[new YamlScalarNode("users")];
            var user = (YamlMappingNode)users[0];
            var userData = (YamlMappingNode)user.Children[new YamlScalarNode("user")];

            if (userData.Children.TryGetValue(new YamlScalarNode("token"), out var tokenNode))
            {
                token = ((YamlScalarNode)tokenNode).Value;
            }
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to extract user/token data: {ex.Message}");
            return null;
        }

        // Validate server URL
        if (string.IsNullOrEmpty(serverUrl))
        {
            report.WriteError("Server URL not found in kubeconfig");
            return null;
        }

        report.WriteBlankLine();
        report.WriteSubHeader("Server URL");
        report.WriteInfo("Validates the API server URL from the kubeconfig cluster entry.");
        report.WriteBlankLine();
        report.WriteField("Server URL", serverUrl);

        Uri serverUri;
        try
        {
            serverUri = new Uri(serverUrl);
            report.WriteField("Scheme", serverUri.Scheme);
            report.WriteField("Host", serverUri.Host);
            report.WriteField("Port", serverUri.Port.ToString());

            if (System.Net.IPAddress.TryParse(serverUri.Host, out var ip))
            {
                report.WriteField("Host Type", $"IP Address ({ip.AddressFamily})");
            }
            else
            {
                report.WriteField("Host Type", "Hostname (DNS)");
            }

            if (serverUri.Scheme != "https")
            {
                report.WriteLabel("Validation:");
                report.WriteWarn($"Server URL uses '{serverUri.Scheme}' scheme instead of 'https'");
            }

            if (!System.Net.IPAddress.TryParse(serverUri.Host, out _))
            {
                report.WriteWarn("DCP typically uses IP addresses — hostname may cause SAN matching issues");
            }
        }
        catch (Exception ex)
        {
            report.WriteError($"Invalid server URL: {ex.Message}");
            return null;
        }

        // Validate token
        if (string.IsNullOrEmpty(token))
        {
            report.WriteLabel("Validation:");
            report.WriteWarn("No bearer token found in kubeconfig");
        }
        else
        {
            report.WriteLabel("Validation:");
            report.WritePass($"Bearer token present ({token.Length} characters)");
        }

        // Validate CA certificate data
        report.WriteBlankLine();
        report.WriteSubHeader("CA Certificate from Kubeconfig");
        report.WriteInfo("Decodes and inspects the certificate-authority-data embedded in the kubeconfig.");
        report.WriteBlankLine();

        if (string.IsNullOrEmpty(caData))
        {
            report.WriteError("certificate-authority-data not found in kubeconfig");
            return null;
        }

        report.WriteField("Base64 Data Length", $"{caData.Length} characters");

        byte[] caCertBytes;
        try
        {
            caCertBytes = Convert.FromBase64String(caData);
            report.WriteInfo($"Base64 decoded successfully ({caCertBytes.Length} bytes)");
        }
        catch (Exception ex)
        {
            report.WriteError($"Base64 decode failed: {ex.Message}");
            return null;
        }

        // Check PEM structure
        var pemString = System.Text.Encoding.UTF8.GetString(caCertBytes);
        report.WriteField("Contains PEM Header", pemString.Contains("-----BEGIN CERTIFICATE-----").ToString());
        report.WriteField("Contains PEM Footer", pemString.Contains("-----END CERTIFICATE-----").ToString());

        // Parse the X509 certificate
        X509Certificate2 caCert;
        try
        {
            caCert = X509CertificateLoader.LoadCertificate(caCertBytes);
            report.WriteInfo("X509Certificate2 created successfully");
        }
        catch (Exception ex)
        {
            report.WriteError($"Failed to create X509Certificate2: {ex.Message}");

            // Try loading from PEM explicitly
            try
            {
                caCert = X509Certificate2.CreateFromPem(pemString);
                report.WriteInfo("Loaded via PEM parsing instead");
            }
            catch (Exception pemEx)
            {
                report.WriteError($"PEM parsing also failed: {pemEx.Message}");
                return null;
            }
        }

        // Log certificate details
        DiagnoseCertificate(caCert, "Kubeconfig CA", report);

        return new KubeconfigData
        {
            ServerUrl = serverUrl,
            Host = serverUri.Host,
            Port = serverUri.Port,
            Token = token ?? "",
            CaCertBytes = caCertBytes,
            CaCertificate = caCert,
            RawYaml = yaml,
        };
    }

    public static void DiagnoseCertificate(X509Certificate2 cert, string label, DiagnosticReport report)
    {
        report.WriteBlankLine();
        report.WriteSubHeader($"Certificate: {label}");

        // --- Data fields ---
        report.WriteField("Subject", cert.Subject);
        report.WriteField("Issuer", cert.Issuer);
        report.WriteField("Thumbprint", cert.Thumbprint);
        report.WriteField("Not Before (UTC)", cert.NotBefore.ToUniversalTime().ToString("O"));
        report.WriteField("Not After (UTC)", cert.NotAfter.ToUniversalTime().ToString("O"));

        var keyAlg = cert.PublicKey.Oid.FriendlyName ?? cert.PublicKey.Oid.Value ?? "unknown";
        var keySize = GetKeySize(cert);
        report.WriteField("Key", keySize != null ? $"{keyAlg} {keySize}-bit" : keyAlg);
        report.WriteField("Signature Algorithm", cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "unknown");

        var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (bc != null)
        {
            report.WriteField("Basic Constraints", $"CA={bc.CertificateAuthority}" +
                (bc.HasPathLengthConstraint ? $", PathLength={bc.PathLengthConstraint}" : ""));
        }

        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (ku != null)
        {
            report.WriteField("Key Usage", ku.KeyUsages.ToString());
        }

        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku != null)
        {
            report.WriteField("Enhanced Key Usage",
                string.Join(", ", eku.EnhancedKeyUsages.Cast<Oid>().Select(o => o.FriendlyName ?? o.Value ?? "?")));
        }

        var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (sanExt != null)
        {
            var dnsNames = sanExt.EnumerateDnsNames().ToList();
            var ipAddresses = sanExt.EnumerateIPAddresses().ToList();

            if (dnsNames.Count > 0)
            {
                report.WriteField("DNS SANs", string.Join(", ", dnsNames));
            }
            if (ipAddresses.Count > 0)
            {
                report.WriteField("IP SANs", string.Join(", ", ipAddresses));
            }
        }

        // --- Validation checks ---
        report.WriteLabel("Validation:");
        var now = DateTime.UtcNow;
        if (now < cert.NotBefore.ToUniversalTime())
        {
            report.WriteFail($"NOT YET VALID (NotBefore is {(cert.NotBefore.ToUniversalTime() - now).TotalMinutes:F1} minutes in the future)");
        }
        else if (now > cert.NotAfter.ToUniversalTime())
        {
            report.WriteFail($"EXPIRED ({(now - cert.NotAfter.ToUniversalTime()).TotalHours:F1} hours ago)");
        }
        else
        {
            var remaining = cert.NotAfter.ToUniversalTime() - now;
            report.WritePass($"Valid ({remaining.TotalDays:F1} days remaining)");
        }

        if (sanExt == null)
        {
            report.WriteWarn($"No Subject Alternative Name extension");
        }
        else
        {
            var dnsNames = sanExt.EnumerateDnsNames().ToList();
            var ipAddresses = sanExt.EnumerateIPAddresses().ToList();
            if (dnsNames.Count == 0 && ipAddresses.Count == 0)
            {
                report.WriteWarn("SAN extension present but contains no DNS or IP entries");
            }
        }
    }

    private static int? GetKeySize(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa != null) return rsa.KeySize;
        }
        catch { /* Not RSA */ }

        try
        {
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa != null) return ecdsa.KeySize;
        }
        catch { /* Not ECDSA */ }

        return null;
    }
}
