using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Indice.Cryptography.AspNetCore.Features;

internal class CertificatesBackgroudService : BackgroundService
{
    private readonly ILogger<CertificatesBackgroudService> _logger;

    public CertificatesBackgroudService(IServiceProvider services, ILogger<CertificatesBackgroudService> logger) {
        Services = services;
        _logger = logger;
    }

    public IServiceProvider Services { get; }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken) {
        _logger.LogInformation("Bootstrapping Certificates...");
        // Run once on start with a slight delay.
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        await DoWork(stoppingToken);
        
    }

    private async Task DoWork(CancellationToken stoppingToken) {
        _logger.LogInformation("Bootstrapping Certificates started.");
        using var scope = Services.CreateScope();
        var options = scope.ServiceProvider.GetRequiredService<CertificateEndpointsOptions>();
        var manager = new CertificateManager();
        var issuingCert = manager.CreateRootCACertificate(options.IssuerDomain);
        var certBase64 = issuingCert.ExportToPEM();
        var pfxBytes = issuingCert.Export(X509ContentType.Pfx, options.PfxPassphrase);
        File.WriteAllBytes(Path.Combine(options.Path, "ca.pfx"), pfxBytes);
        File.WriteAllText(Path.Combine(options.Path, "ca.cer"), certBase64);
        var store = scope.ServiceProvider.GetService<ICertificatesStore>();
        await store.Add(issuingCert, null!);
    }

    public override async Task StopAsync(CancellationToken stoppingToken) {
        _logger.LogInformation("Bootstrapping Certificates ended.");
        await base.StopAsync(stoppingToken);
    }

}