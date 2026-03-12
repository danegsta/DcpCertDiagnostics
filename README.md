# DCP Certificate Trust Diagnostic Tool

A standalone .NET diagnostic tool that starts a DCP instance, connects to it using the `KubernetesClient` library (the same library Aspire uses), and captures comprehensive certificate and TLS diagnostic information.

## Purpose

Some users experience certificate trust failures when Aspire connects to DCP's self-signed certificates. The errors are inconsistent across platforms and lack detail. This tool captures everything needed to diagnose the root cause:

- **Environment details**: OS, .NET runtime, TLS provider (OpenSSL/SChannel), system trust store state
- **Certificate analysis**: Full details of both the kubeconfig CA cert and the server-presented cert
- **Chain validation**: Multiple X509Chain.Build() attempts with different trust policies
- **IP SAN matching**: Whether the server cert's SANs match the connection target
- **KubernetesClient behavior**: What happens when the actual KubernetesClient library tries to connect
- **Full exception chains**: Every inner exception and stack frame captured

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (or later)

## Quick Start

```bash
# Build and run (DCP binary is downloaded automatically via NuGet):
dotnet run
```

The tool will:
1. Download the correct DCP binary for your platform (via the `Aspire.Hosting.Orchestration` NuGet package)
2. Start DCP in API server-only mode
3. Parse the generated kubeconfig and analyze the CA certificate
4. Check proxy configuration for the DCP server URL (proxies can cause TLS trust failures)
5. Connect via raw `SslStream` to capture the full TLS handshake details
6. Connect via `KubernetesClient` (same path as Aspire) with detailed logging
7. Output a diagnostic report to both the console and a timestamped file

## Options

| Option | Description |
|--------|-------------|
| `--dcp-path <path>` | Use a custom DCP binary instead of the NuGet package |
| `--output, -o <path>` | Custom path for the report file (default: `dcp-cert-diagnostic-<timestamp>.txt`) |
| `--help, -h` | Show help |

## Using a Custom DCP Binary

If you have a locally-built DCP binary (e.g., from the repo's `bin/` directory):

```bash
dotnet run -- --dcp-path /path/to/dcp
```

## What to Share

After running the tool, share the generated report file (e.g., `dcp-cert-diagnostic-20250101-120000.txt`). The report contains:

- No secrets or tokens (bearer tokens are redacted to show only length)
- Certificate details (subjects, validity, extensions, SANs)
- Chain validation results with all status codes
- Exception details with stack traces
- Environment information

## Understanding the Output

The report uses color-coded status indicators:

- **✓ PASS** (green): A check passed — this aspect is working correctly
- **✗ FAIL** (red): A check failed — this is a potential problem area
- **⚠ WARN** (yellow): A warning — something unusual that may or may not be a problem
- **ℹ INFO** (cyan): Informational — context for understanding results
- **✗ ERROR** (red): A critical error that prevented further diagnostics

### Key Sections

1. **Environment Info**: Verifies the OS, .NET runtime, and TLS provider are as expected
2. **DCP Binary Resolution**: Confirms the DCP binary was found and its version
3. **Kubeconfig Analysis**: Validates the CA cert from the kubeconfig file
4. **Certificate Chain Analysis**: The most diagnostic section — shows what happens at the TLS level
5. **KubernetesClient Diagnostic**: Shows what happens through the same code path as Aspire

### Common Issues This Tool Can Detect

- **Clock skew**: Certificate NotBefore/NotAfter validation failures
- **Missing IP SANs**: Server cert doesn't include the connection IP
- **Revocation check failures**: CRL/OCSP checks failing for self-signed certs
- **Chain building failures**: CA cert not being trusted or chain incomplete
- **Platform differences**: OpenSSL vs SChannel handling IP SANs differently
- **Environment interference**: SSL_CERT_FILE/SSL_CERT_DIR overriding trust stores

## Architecture

```
Program.cs                    → Entry point, orchestrates the diagnostic flow
├── EnvironmentInfo.cs        → Collects OS, .NET, TLS provider details
├── DcpProcessManager.cs      → Resolves DCP binary, starts/stops DCP process
├── KubeconfigParser.cs       → Parses kubeconfig YAML, validates CA certificate
├── CertificateAnalyzer.cs    → Raw SslStream connection, chain building tests
└── KubernetesClientDiagnostic.cs → KubernetesClient with diagnostic callbacks
```

`DiagnosticReport.cs` is used by all components to collect and format output.
