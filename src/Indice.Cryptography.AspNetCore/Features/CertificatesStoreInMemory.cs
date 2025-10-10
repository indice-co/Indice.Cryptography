using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Indice.Cryptography.AspNetCore.Features;

internal class CertificatesStoreInMemory : ICertificatesStore
{
    public Task<CertificateDetails> Add(CertificateDetails certificate, string subject, string thumbprint, object metadata, bool isCA) {
        throw new NotImplementedException();
    }

    public Task<CertificateDetails> GetById(string keyId) {
        throw new NotImplementedException();
    }

    public Task<List<CertificateDetails>> GetList(DateTimeOffset? notBefore = null, bool? revoked = null, string authorityKeyId = null) {
        throw new NotImplementedException();
    }

    public Task<List<RevokedCertificateDetails>> GetRevocationList(DateTimeOffset? notBefore = null) {
        throw new NotImplementedException();
    }

    public Task Revoke(string keyId) {
        throw new NotImplementedException();
    }
}
