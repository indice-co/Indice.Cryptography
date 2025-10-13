using System;

namespace Indice.Cryptography.AspNetCore.Features;

/// <summary>
/// Certificate creation response.
/// </summary>
public class CertificateDetails
{
    /// <summary>
    /// Base 64 Pem encoded cer.
    /// </summary>
    public string? EncodedCert { get; set; }
    /// <summary>
    /// Private key base64.
    /// </summary>
    public string? PrivateKey { get; set; }
    /// <summary>
    /// Subject Key Identifier.
    /// </summary>
    public string? KeyId { get; set; }
    /// <summary>
    /// Serial number.
    /// </summary>
    public string? SerialNumber { get; set; }
    /// <summary>
    /// Authority Subject Key Identifier (issuing certificate Subject Key Identifier).
    /// </summary>
    public string? AuthorityKeyId { get; set; }
    /// <summary>
    /// SHA256WITHRSA.
    /// </summary>
    public string? Algorithm { get; set; }
}

/// <summary>
/// Used to select revoked certificates
/// </summary>
public class RevokedCertificateDetails
{
    /// <summary>
    /// Serial number.
    /// </summary>
    public string SerialNumber { get; set; } = null!;
    /// <summary>
    /// Indicates the revoked date.
    /// </summary>
    public DateTime RevocationDate { get; set; }
}
