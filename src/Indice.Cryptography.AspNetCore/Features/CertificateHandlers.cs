using Indice.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Indice.Cryptography.AspNetCore.Features;
internal static class CertificateHandlers
{
    public static FileStreamHttpResult GetIssuerCertificate(CertificateEndpointsOptions options) {
        var file = new FileInfo(Path.Combine(options.Path!, "ca.cer"));
        return TypedResults.File(file.OpenRead(), contentType: "application/x-x509-ca-cert", fileDownloadName: "ca.cer", lastModified: file.LastWriteTimeUtc);
    }

    public static async Task<Ok<CertificateDetails>> CreateCertificate(
            ICertificatesStore store, 
            CertificateEndpointsOptions options, 
            Psd2CertificateRequest request) {
        var issuer = new X509Certificate2(Path.Combine(options.Path!, "ca.pfx"), options.PfxPassphrase, X509KeyStorageFlags.MachineKeySet);
        var manager = new CertificateManager();
        var cert = manager.CreateQualifiedCertificate(request, options.IssuerDomain, issuer, out _);
        var response = await store.Add(cert, request);
        cert.Dispose();
        return TypedResults.Ok(response);
    }

    public static async Task<Results<CertificateHttpResult, NotFound, ValidationProblem>> Export(
            ICertificatesStore store,
            CertificateEndpointsOptions options,
            string keyId, string format, string? password) {
        var response = await store.GetById(keyId);
        if (response == null) {
            return TypedResults.NotFound();
        }
        if (format.ToLower() == "pfx" && string.IsNullOrEmpty(password)) {
            var errors = new Dictionary<string, string[]> {
                [nameof(password)] = ["A password is required in order to export to pfx"]
            };
            return TypedResults.ValidationProblem(errors);
        }
        return Results.Extensions.Certificate(response, format, password);
    }

    public static async Task<NoContent> Revoke(
            ICertificatesStore store,
            string keyId) {
        await store.Revoke(keyId);
        return TypedResults.NoContent();
    }

    public static async Task<Ok<List<CertificateDetails>>> GetList(
            ICertificatesStore store,
            DateTimeOffset? notBefore, bool? revoked, string? authorityKeyId) {
        var results = await store.GetList(notBefore, revoked, authorityKeyId);
        return TypedResults.Ok(results);
    }

    public static async Task<FileContentHttpResult> RevocationList(
            ICertificatesStore store,
            CertificateEndpointsOptions options) {
        var issuer = new X509Certificate2(Path.Combine(options.Path!, "ca.pfx"), options.PfxPassphrase);
        var results = await store.GetRevocationList();
        var crl = new CertificateRevocationList {
            AuthorizationKeyId = issuer.GetSubjectKeyIdentifier()?.ToLower(),
            Country = "GR",
            Organization = "Sample Authority",
            IssuerCommonName = "Some Cerification Authority CA",
            CrlNumber = 234,
            EffectiveDate = results.OrderByDescending(x => x.RevocationDate).Select(x => (DateTime?)x.RevocationDate).FirstOrDefault() ?? DateTime.UtcNow,
            NextUpdate = DateTime.UtcNow.AddDays(1),
            Items = results.Select(x => new RevokedCertificate {
                ReasonCode = RevokedCertificate.CRLReasonCode.Superseded,
                RevocationDate = x.RevocationDate,
                SerialNumber = x.SerialNumber
            })
            .ToList()
        };
        var crlSeq = new CertificateRevocationListSequence(crl);
        var data = crlSeq.SignAndSerialize(issuer.GetRSAPrivateKey()!);
        return TypedResults.File(data, contentType:"application/x-pkcs7-crl", fileDownloadName: "revoked.crl", lastModified: (DateTimeOffset)crl.EffectiveDate);
    }
}