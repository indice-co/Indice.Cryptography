using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Indice.Cryptography.AspNetCore.Middleware;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extensions related to configuring the <see cref="HttpSignatureMiddleware"/> on the <seealso cref="IServiceCollection"/>
/// </summary>
public static class HttpSignatureConfiguration
{
    /// <summary>
    /// Adds HTTP signature related services to the specified <see cref="IServiceCollection"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="setupAction"></param>
    /// <returns></returns>
    public static IHttpSignatureBuilder AddHttpSignatures(this IServiceCollection services, Action<HttpSignatureOptions>? setupAction = null) {
        var builder = new HttpSignatureBuilder {
            Services = services
        };
        var existingService = services.Where(x => x.ServiceType == typeof(HttpSignatureOptions)).LastOrDefault();
        if (existingService == null) {
            var options = new HttpSignatureOptions();
            setupAction?.Invoke(options);
            services.AddSingleton(options);
            builder.Options = options;
        }
        builder.Services.AddSingleton<IHttpClientValidationKeysStore, DefaultHttpClientValidationKeysStore>();
        return builder;
    }

    /// <summary>
    /// Sets the signing credential.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="credential">The credential.</param>
    /// <returns></returns>
    public static IHttpSignatureBuilder AddSigningCredential(this IHttpSignatureBuilder builder, SigningCredentials credential) {
        if (!(credential.Key is AsymmetricSecurityKey || (credential.Key is JsonWebKey key && key.HasPrivateKey))) {
            throw new InvalidOperationException("Signing key is not asymmetric.");
        }
        builder.Services.AddSingleton<IHttpSigningCredentialsStore>(new DefaultHttpSigningCredentialsStore(credential));
        builder.Services.AddSingleton<IHttpValidationKeysStore>(new DefaultHttpValidationKeysStore(new[] { credential.Key }));
        var options = ((HttpSignatureBuilder)builder).Options;
        if (!options.ResponseSigning.HasValue) {
            options.ResponseSigning = true;
        }
        return builder;
    }

    /// <summary>
    /// Sets the signing credential.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="certificate">The certificate.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException">X509 certificate does not have a private key.</exception>
    public static IHttpSignatureBuilder AddSigningCredential(this IHttpSignatureBuilder builder, X509Certificate2 certificate) {
        if (certificate == null) throw new ArgumentNullException(nameof(certificate));
        if (!certificate.HasPrivateKey) {
            throw new InvalidOperationException("X509 certificate does not have a private key.");
        }
        var credential = new SigningCredentials(new X509SecurityKey(certificate), "RS256");
        return builder.AddSigningCredential(credential);
    }

    /// <summary>
    /// Sets the signing credential.
    /// </summary>
    /// <param name="builder">The builder.</param>
    /// <param name="rsaKey">The RSA key.</param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException">RSA key does not have a private key.</exception>
    public static IHttpSignatureBuilder AddSigningCredential(this IHttpSignatureBuilder builder, RsaSecurityKey rsaKey) {
        if (rsaKey.PrivateKeyStatus == PrivateKeyStatus.DoesNotExist) {
            throw new InvalidOperationException("RSA key does not have a private key.");
        }
        var credential = new SigningCredentials(rsaKey, "RS256");
        return builder.AddSigningCredential(credential);
    }
}

internal class HttpSignatureBuilder : IHttpSignatureBuilder
{
    public IServiceCollection Services { get; set; } = null!;
    public HttpSignatureOptions Options { get; set; } = null!;
}
