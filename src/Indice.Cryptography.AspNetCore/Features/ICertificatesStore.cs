using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Indice.Cryptography.AspNetCore.Features;

/// <summary>
/// Certificate store used to persist the issued certificates.
/// </summary>
public interface ICertificatesStore {
    /// <summary>
    /// Stores the certificate
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="subject">The distinguished name of the issued certificate</param>
    /// <param name="thumbprint"></param>
    /// <param name="metadata">Any metadata</param>
    /// <param name="isCA">Is certificate authority. marks an issuing certificate</param>
    /// <returns>the stored certificate</returns>
    Task<CertificateDetails> Add(CertificateDetails certificate, string subject, string thumbprint, object metadata, bool isCA);
    /// <summary>
    /// Revokes a certificate by key Id
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    Task Revoke(string keyId);
    /// <summary>
    /// Retrieves a stored certificate by Id
    /// </summary>
    /// <param name="keyId"></param>
    /// <returns></returns>
    Task<CertificateDetails> GetById(string keyId);
    /// <summary>
    /// Gets list of certificates by parameters
    /// </summary>
    /// <param name="notBefore"></param>
    /// <param name="revoked"></param>
    /// <param name="authorityKeyId"></param>
    /// <returns></returns>
    Task<List<CertificateDetails>> GetList(DateTimeOffset? notBefore = null, bool? revoked = null, string authorityKeyId = null);
    /// <summary>
    /// Gets list of certificates by parameters
    /// </summary>
    /// <param name="notBefore"></param>
    /// <returns></returns>
    Task<List<RevokedCertificateDetails>> GetRevocationList(DateTimeOffset? notBefore = null);
}

/// <summary>
/// <see cref="ICertificatesStore"/> extensions.
/// </summary>
public static class CertificateStoreExtensions
{
    /// <summary>
    /// Helper method add via <see cref="X509Certificate2"/>
    /// </summary>
    /// <param name="store">the store</param>
    /// <param name="certificate">The certificate</param>
    /// <param name="metadata"></param>
    /// <returns></returns>
    public static async Task<CertificateDetails> Add(this ICertificatesStore store, X509Certificate2 certificate, object metadata) {
        var privateKey = certificate.GetRSAPrivateKey();
        var certBase64 = certificate.ExportToPEM();
        //var publicBase64 = privateKey.ToSubjectPublicKeyInfo();
        var privateBase64 = privateKey.ToRSAPrivateKey();
        var keyId = certificate.GetSubjectKeyIdentifier();
        var authkeyId = certificate.GetAuthorityKeyIdentifier();
        var isCA = certificate.IsCertificateAuthority();
        var response = await store.Add(new CertificateDetails {
            EncodedCert = certBase64,
            PrivateKey = privateBase64,
            KeyId = keyId.ToLower(),
            SerialNumber = certificate.SerialNumber?.ToLower(),
            AuthorityKeyId = authkeyId?.ToLower(),
            Algorithm = "sha256RSA"
        }, 
        certificate.Subject, certificate.Thumbprint, metadata, isCA);
        return response;
    }
}
