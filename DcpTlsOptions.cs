using System.Diagnostics;

namespace DcpCertDiagnostic;

internal sealed class DcpTlsOptions : IDisposable
{
    private readonly string? _temporaryDirectory;

    private DcpTlsOptions(
        string? certThumbprint,
        string? certFile,
        string? keyFile,
        string? caFile,
        string? temporaryDirectory)
    {
        CertThumbprint = certThumbprint;
        CertFile = certFile;
        KeyFile = keyFile;
        CaFile = caFile;
        _temporaryDirectory = temporaryDirectory;
    }

    public string? CertThumbprint { get; }

    public string? CertFile { get; }

    public string? KeyFile { get; }

    public string? CaFile { get; }

    public static DcpTlsOptions FromThumbprint(string certThumbprint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certThumbprint);

        return new DcpTlsOptions(certThumbprint, certFile: null, keyFile: null, caFile: null, temporaryDirectory: null);
    }

    public static DcpTlsOptions FromCertificateFiles(
        string certFile,
        string keyFile,
        string certThumbprint,
        string? caFile = null,
        string? temporaryDirectory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyFile);
        ArgumentException.ThrowIfNullOrWhiteSpace(certThumbprint);

        return new DcpTlsOptions(certThumbprint, certFile, keyFile, caFile, temporaryDirectory);
    }

    public void AddTlsArguments(ProcessStartInfo startInfo)
    {
        if (!string.IsNullOrEmpty(CertFile))
        {
            startInfo.ArgumentList.Add("--tls-cert-file");
            startInfo.ArgumentList.Add(CertFile);
        }

        if (!string.IsNullOrEmpty(KeyFile))
        {
            startInfo.ArgumentList.Add("--tls-key-file");
            startInfo.ArgumentList.Add(KeyFile);
        }

        if (!string.IsNullOrEmpty(CertThumbprint))
        {
            startInfo.ArgumentList.Add("--tls-cert-thumbprint");
            startInfo.ArgumentList.Add(CertThumbprint);
        }

        if (!string.IsNullOrEmpty(CaFile))
        {
            startInfo.ArgumentList.Add("--tls-ca-file");
            startInfo.ArgumentList.Add(CaFile);
        }
    }

    public void Dispose()
    {
        if (_temporaryDirectory == null)
        {
            return;
        }

        try
        {
            if (Directory.Exists(_temporaryDirectory))
            {
                Directory.Delete(_temporaryDirectory, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
