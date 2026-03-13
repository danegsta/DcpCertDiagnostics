using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DcpCertDiagnostic;

/// <summary>
/// Checks for the ASP.NET Core HTTPS development certificate and verifies
/// that a certificate chain can be built for it (i.e., it is trusted).
/// </summary>
internal static class DevCertDiagnostic
{
    /// <summary>
    /// The well-known OID used by <c>dotnet dev-certs https</c> to mark the
    /// ASP.NET Core HTTPS development certificate.
    /// </summary>
    private const string AspNetHttpsOid = "1.3.6.1.4.1.311.84.1.1";

    public static void Diagnose(DiagnosticReport report)
    {
        report.WriteHeader("ASP.NET Core Development Certificate");

        X509Certificate2Collection devCerts;
        try
        {
            devCerts = FindDevCertificates();
        }
        catch (Exception ex)
        {
            report.WriteWarn($"Unable to search for dev certificates: {ex.Message}");
            return;
        }

        if (devCerts.Count == 0)
        {
            report.WriteInfo("No ASP.NET Core HTTPS development certificate found in the CurrentUser/My store.");
            report.WriteInfo("This is expected if you have not run 'dotnet dev-certs https' or are not using dev certs.");
            return;
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

            ReportCertDetails(cert, report);
            CheckExpiration(cert, report);
            CheckChainBuild(cert, report);

            if (i < devCerts.Count - 1)
            {
                report.WriteBlankLine();
            }
        }
    }

    private static X509Certificate2Collection FindDevCertificates()
    {
        var results = new X509Certificate2Collection();

        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);

        foreach (var cert in store.Certificates)
        {
            if (HasAspNetHttpsOid(cert))
            {
                results.Add(new X509Certificate2(cert));
            }
        }

        return results;
    }

    private static bool HasAspNetHttpsOid(X509Certificate2 cert)
    {
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value == AspNetHttpsOid)
            {
                return true;
            }
        }

        return false;
    }

    private static void ReportCertDetails(X509Certificate2 cert, DiagnosticReport report)
    {
        report.WriteField("Subject", cert.Subject);
        report.WriteField("Issuer", cert.Issuer);
        report.WriteField("Thumbprint", cert.Thumbprint);
        report.WriteField("Not Before (UTC)", cert.NotBefore.ToUniversalTime().ToString("O"));
        report.WriteField("Not After (UTC)", cert.NotAfter.ToUniversalTime().ToString("O"));
        report.WriteField("Key Algorithm", $"{cert.PublicKey.Oid.FriendlyName} ({cert.PublicKey.GetRSAPublicKey()?.KeySize ?? cert.PublicKey.GetECDsaPublicKey()?.KeySize ?? 0}-bit)");

        var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (sanExt != null)
        {
            var dnsNames = sanExt.EnumerateDnsNames().ToList();
            if (dnsNames.Count > 0)
            {
                report.WriteField("SAN DNS Names", string.Join(", ", dnsNames));
            }
        }
    }

    private static void CheckExpiration(X509Certificate2 cert, DiagnosticReport report)
    {
        report.WriteLabel("Expiration:");

        var now = DateTime.UtcNow;

        if (now < cert.NotBefore.ToUniversalTime())
        {
            report.WriteFail($"NOT YET VALID (NotBefore is {(cert.NotBefore.ToUniversalTime() - now).TotalMinutes:F1} minutes in the future)");
        }
        else if (now > cert.NotAfter.ToUniversalTime())
        {
            report.WriteFail($"EXPIRED ({(now - cert.NotAfter.ToUniversalTime()).TotalDays:F1} days ago)");
        }
        else
        {
            var remaining = cert.NotAfter.ToUniversalTime() - now;
            if (remaining.TotalDays < 30)
            {
                report.WriteWarn($"Expiring soon ({remaining.TotalDays:F1} days remaining)");
            }
            else
            {
                report.WritePass($"Valid ({remaining.TotalDays:F0} days remaining)");
            }
        }
    }

    private static void CheckChainBuild(X509Certificate2 cert, DiagnosticReport report)
    {
        report.WriteLabel("Chain Build (System Trust):");

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;

        try
        {
            bool result = chain.Build(cert);

            if (result)
            {
                report.WritePass("Chain built successfully — dev certificate is trusted");
            }
            else
            {
                report.WriteFail("Chain build failed — dev certificate is NOT trusted");
                report.WriteInfo("Run 'dotnet dev-certs https --trust' to trust the dev certificate.");

                foreach (var status in chain.ChainStatus)
                {
                    report.WriteField("  Chain Status", $"{status.Status}: {status.StatusInformation}");
                }

                WritePerElementChainStatus(chain, report);
            }
        }
        catch (Exception ex)
        {
            report.WriteFail($"Chain build threw an exception: {ex.Message}");
            report.WriteField("  HResult", $"0x{ex.HResult:X8}");

            if (chain.ChainElements.Count > 0)
            {
                report.WriteField("  Elements Built", chain.ChainElements.Count.ToString());
                WritePerElementChainStatus(chain, report);
            }

            if (ex.InnerException != null)
            {
                report.WriteField("  Inner Exception", ex.InnerException.Message);
            }
        }
    }

    private static void WritePerElementChainStatus(X509Chain chain, DiagnosticReport report)
    {
        for (int i = 0; i < chain.ChainElements.Count; i++)
        {
            var element = chain.ChainElements[i];
            foreach (var status in element.ChainElementStatus)
            {
                report.WriteField($"  Element[{i}] ({element.Certificate.Subject})",
                    $"{status.Status}: {status.StatusInformation}");
            }
        }
    }
}
