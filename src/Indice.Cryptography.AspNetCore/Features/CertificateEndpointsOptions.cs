namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Configuration options for certificate endpoints feature.
/// </summary>
public class CertificateEndpointsOptions
{
    /// <summary>
    /// Path to where CA certificate should be stored/retrieved.
    /// </summary>
    public string? Path { get; set; }
    /// <summary>
    /// The domain name where this application is hosted. Ex https://example.com
    /// </summary>
    public string IssuerDomain { get; set; } = null!;
    /// <summary>
    /// The PFX passphrase for the issuer certs.
    /// </summary>
    public string PfxPassphrase { get; set; } = null!;

    internal IServiceCollection Services = null!;
}
