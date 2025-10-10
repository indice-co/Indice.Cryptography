using Indice.Cryptography.AspNetCore.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.AspNetCore.Builder;
/// <summary>
/// Maps the certificate store endpoints
/// </summary>
public static class CertificateApi
{
    /// <summary>
    ///  Maps the certificate store endpoints
    /// </summary>
    /// <param name="routes">The <see cref="IEndpointRouteBuilder"/></param>
    /// <returns>The builder</returns>
    public static IEndpointRouteBuilder MapCertificateStore(this IEndpointRouteBuilder routes) {
        var group = routes.MapGroup(".certificates");
        group.WithGroupName("cert")
             .WithTags("Certificates")
             .WithOpenApi();
        var options = routes.ServiceProvider.GetRequiredService<CertificateEndpointsOptions>();

        group.MapGet("ca.cer", CertificateHandlers.GetIssuerCertificate)
             .WithName(nameof(CertificateHandlers.GetIssuerCertificate))
             .WithSummary("Get issuer certificate.");
             //.Produces(StatusCodes.Status200OK, contentType:"application/x-x509-ca-cert", responseType: null);
        
        group.MapPost("", CertificateHandlers.CreateCertificate)
             .WithName(nameof(CertificateHandlers.CreateCertificate))
             .WithSummary("Generates an X509Certificate.");

        group.MapGet("{keyId}.{format}", CertificateHandlers.Export)
             .WithName(nameof(CertificateHandlers.Export))
             .WithSummary("Exports a certificates.");

        group.MapPut("{keyId}/revoke", CertificateHandlers.Revoke)
             .WithName(nameof(CertificateHandlers.Revoke))
             .WithSummary("Revoke a certificate.");

        group.MapGet("", CertificateHandlers.GetList)
             .WithName(nameof(CertificateHandlers.GetList))
             .WithSummary("List all available certificates.");

        group.MapGet("revoked.crl", CertificateHandlers.RevocationList)
             .WithName(nameof(CertificateHandlers.RevocationList))
             .WithSummary("Certificate revocation list.");
             //.Produces(StatusCodes.Status200OK, contentType: "application/x-pkcs7-crl", responseType:null);

        return routes;
    }
}