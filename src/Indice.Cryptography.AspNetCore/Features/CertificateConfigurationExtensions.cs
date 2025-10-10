using System;
using System.IO;
using Indice.Cryptography.AspNetCore.Features;
using Indice.Cryptography.AspNetCore.Features.EF;
using Microsoft.AspNetCore.Hosting;

namespace Microsoft.Extensions.DependencyInjection;
/// <summary>
/// Configuration extensions for certificate server feature
/// </summary>
public static class CertificateConfigurationExtensions
{

    /// <summary>
    /// Add the Certificate endpoints feature.
    /// </summary>
    /// <param name="services">An interface for configuring Services.</param>
    /// <param name="hostEnvironment">The hosting environment</param>
    /// <param name="configureAction">Delegate for configuring options for certificate endpoints feature.</param>
    /// <returns></returns>
    public static IServiceCollection AddCertificateServer(this IServiceCollection services, IWebHostEnvironment hostEnvironment, Action<CertificateEndpointsOptions> configureAction = null!) {
        AddCertificateServerInternal(services, hostEnvironment, configureAction);
        services.AddEndpointsApiExplorer();
        return services;
    }

    /// <summary>
    /// Add the Certificate endpoints feature.
    /// </summary>
    /// <param name="services">An interface for configuring Services.</param>
    /// <param name="hostEnvironment">The hosting environment</param>
    /// <param name="configureAction">Delegate for configuring options for certificate endpoints feature.</param>
    /// <returns></returns>
    internal static IServiceCollection AddCertificateServerInternal(this IServiceCollection services, IWebHostEnvironment hostEnvironment, Action<CertificateEndpointsOptions> configureAction = null!) {
        var options = new CertificateEndpointsOptions {
            IssuerDomain = "www.example.com",
            PfxPassphrase = "???"
        };
        options.Services = services;
        configureAction?.Invoke(options);
        options.Services = null!;
        if (options.Path == null) {
            options.Path = Path.Combine(hostEnvironment.ContentRootPath, "App_Data", "certs");
        }
        services.AddSingleton(options);
        if (!Directory.Exists(options.Path)) {
            Directory.CreateDirectory(options.Path);
        }
        if (!File.Exists(Path.Combine(options.Path, "ca.pfx"))) {
            // bootstrap
            services.AddHostedService<CertificatesBackgroudService>();
        }
        return services;
    }

    /// <summary>
    /// Backs up the certificates into a database.
    /// </summary>
    /// <param name="options">Configuration options for certificate endpoints feature.</param>
    /// <param name="configureAction">Delegate for configuring options for the CertificatesStore context.</param>
    public static void AddEntityFrameworkStore(this CertificateEndpointsOptions options, Action<CertificatesStoreOptions> configureAction) {
        var storeOptions = new CertificatesStoreOptions {
            DefaultSchema = "cert"
        };
        configureAction?.Invoke(storeOptions);
        options.Services.AddSingleton(storeOptions);
        if (storeOptions.ResolveDbContextOptions != null) {
            options.Services.AddDbContext<CertificatesDbContext>(storeOptions.ResolveDbContextOptions);
        } else {
            options.Services.AddDbContext<CertificatesDbContext>(storeOptions.ConfigureDbContext);
        }
        options.Services.AddTransient<ICertificatesStore, DbCertificatesStore>();
    }
}
