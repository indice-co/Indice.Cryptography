using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Indice.Cryptography.AspNetCore.Features.EF;

/// <summary>
/// Entity framework implementation of <see cref="ICertificatesStore"/>
/// </summary>
public class DbCertificatesStore : ICertificatesStore
{
    /// <summary>
    /// Creates a new instance of <see cref="DbCertificatesStore"/>.
    /// </summary>
    public DbCertificatesStore(CertificatesDbContext dbContext) {
        DbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
    }

    /// <summary>
    /// The <see cref="CertificatesDbContext"/>.
    /// </summary>
    protected CertificatesDbContext DbContext { get; }

    /// <summary>
    /// Retrieves a stored certificate by Id.
    /// </summary>
    /// <param name="keyId">The id to search for.</param>
    public async Task<CertificateDetails> GetById(string keyId) {
        var cert = default(CertificateDetails);
        var dbCert = await DbContext.Certificates.FindAsync(keyId);
        if (dbCert != null && !dbCert.Revoked) {
            cert = MapToDetails(dbCert);
        }
        return cert;
    }

    /// <summary>
    /// Gets list of certificates by parameters.
    /// </summary>
    /// <param name="notBefore"></param>
    /// <param name="revoked"></param>
    /// <param name="authorityKeyId"></param>
    public async Task<List<CertificateDetails>> GetList(DateTimeOffset? notBefore = null, bool? revoked = null, string authorityKeyId = null) {
        var results = await DbContext.Certificates
                                     .Where(x => (notBefore == null || x.CreatedDate >= notBefore)
                                              && (revoked == null || x.Revoked == revoked)
                                              && (authorityKeyId == null || x.AuthorityKeyId == authorityKeyId))
                                     .ToListAsync();
        return results.Select(x => MapToDetails(x)).ToList();
    }
    /// <summary>
    /// Gets list of certificates by parameters.
    /// </summary>
    /// <param name="notBefore"></param>
    public async Task<List<RevokedCertificateDetails>> GetRevocationList(DateTimeOffset? notBefore = null) {
        var results = await DbContext.Certificates
                                     .Where(x => (notBefore == null || x.CreatedDate >= notBefore)
                                               && x.Revoked == true)
                                     .ToListAsync();
        return results.Select(x => new RevokedCertificateDetails {
            RevocationDate = x.RevocationDate.Value,
            SerialNumber = x.SerialNumber
        })
        .ToList();
    }

    /// <summary>
    /// Revokes a certificate by key Id.
    /// </summary>
    /// <param name="keyId">The id of the certificate to delete.</param>
    public async Task Revoke(string keyId) {
        var dbCert = await DbContext.Certificates.FindAsync(keyId);
        if (dbCert != null && !dbCert.Revoked) {
            dbCert.Revoked = true;
            dbCert.RevocationDate = DateTime.UtcNow;
            await DbContext.SaveChangesAsync();
        }
    }
    /// <summary>
    /// Stores the certificate.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="subject">The distinguished name of the issued certificate.</param>
    /// <param name="thumbprint"></param>
    /// <param name="metadata">Any metadata.</param>
    /// <param name="isCA">Is certificate authority. Marks an issuing certificate.</param>
    /// <returns>The stored certificate.</returns>
    public async Task<CertificateDetails> Add(CertificateDetails certificate, string subject, string thumbprint, object metadata, bool isCA) {
        var dbCert = await DbContext.Certificates.FindAsync(certificate.KeyId);
        if (dbCert != null) {
            throw new Exception($"There is already a certificate with the same Subject Key Identifier \"{dbCert.KeyId}\"in the store.");
        }
        DbContext.Certificates.Add(new DbCertificate {
            KeyId = certificate.KeyId,
            Algorithm = certificate.Algorithm,
            AuthorityKeyId = certificate.AuthorityKeyId,
            EncodedCert = certificate.EncodedCert,
            PrivateKey = certificate.PrivateKey,
            Subject = subject,
            Thumbprint = thumbprint,
            SerialNumber = certificate.SerialNumber,
            Data = metadata == null ? null : JsonSerializer.Serialize(metadata, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
            IsCA = isCA,
            Revoked = false,
            RevocationDate = null,
            CreatedDate = DateTime.UtcNow
        });
        await DbContext.SaveChangesAsync();
        return certificate;
    }

    private CertificateDetails MapToDetails(DbCertificate dbCert) {
        return new CertificateDetails {
            Algorithm = dbCert.Algorithm,
            AuthorityKeyId = dbCert.AuthorityKeyId,
            EncodedCert = dbCert.EncodedCert,
            KeyId = dbCert.KeyId,
            PrivateKey = dbCert.PrivateKey,
            SerialNumber = dbCert.SerialNumber
        };
    }
}
