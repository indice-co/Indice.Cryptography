using System;

namespace Indice.Cryptography.AspNetCore.Features.EF;

/// <summary>
/// Database spesific entity that stores an issued certificate.
/// </summary>
public class DbCertificate
{
    /// <summary>
    /// Base 64 Pem encoded cer
    /// </summary>
    public string? EncodedCert { get; set; }
    /// <summary>
    /// Private key base64
    /// </summary>
    public string? PrivateKey { get; set; }
    /// <summary>
    /// Subject Key Identifier
    /// </summary>
    public string KeyId { get; set; } = null!;
    /// <summary>
    /// Serial number
    /// </summary>
    public string? SerialNumber { get; set; }
    /// <summary>
    /// Authority Subject Key Identifier (issuing certificate Subject Key Identifier)
    /// </summary>
    public string? AuthorityKeyId { get; set; }
    /// <summary>
    /// SHA256WITHRSA
    /// </summary>
    public string? Algorithm { get; set; }
    /// <summary>
    /// The certificate thumbprint
    /// </summary>
    public string? Thumbprint { get; set; }
    /// <summary>
    /// The certificate Distinguished name
    /// </summary>
    public string? Subject { get; set; }
    /// <summary>
    /// The data used to create this
    /// </summary>
    public string? Data { get; set; }
    /// <summary>
    /// Is certificate authority. marks an issuing certificate
    /// </summary>
    public bool IsCA { get; set; }
    /// <summary>
    /// Indicates a revoked certificate.
    /// </summary>
    public bool Revoked { get; set; }
    /// <summary>
    /// Indicates the creation date.
    /// </summary>
    public DateTime CreatedDate { get; set; }
    /// <summary>
    /// Indicates the revoked date.
    /// </summary>
    public DateTime? RevocationDate { get; set; }
}
