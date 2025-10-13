using System.Security.Cryptography.X509Certificates;
using Indice.Cryptography.Host.Swagger;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddCertificateServer(builder.Environment, options => {
    options.IssuerDomain = builder.Configuration["Certificates:Issuer"]!;
    options.AddEntityFrameworkStore(sqlOptions => {
        sqlOptions.ConfigureDbContext = sqlbuilder => {
            sqlbuilder.UseSqlServer(builder.Configuration.GetConnectionString("CertificatesDb"));
        };
    });
});

builder.Services.AddSwaggerGen(options => {
    options.SchemaFilter<SchemaExamplesFilter>();
    options.SwaggerDoc("cert", new OpenApiInfo {
        Description = "Certificate *utilities*",
        Title = "Certificate",
        Version = "v1"
    });
    var xmlFiles = new[] {
                $"{typeof(Program).Assembly.GetName().Name}.xml",
                "Indice.Cryptography.AspNetCore.xml",
                "Indice.Cryptography.xml"
            };
    foreach (var xmlFile in xmlFiles) {
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        if (File.Exists(xmlPath)) {
            options.IncludeXmlComments(xmlPath);
        }
    }
});
#if NET9_0_OR_GREATER

var httpSignatureCertificate = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(builder.Environment.ContentRootPath, builder.Configuration["HttpSignatures:PfxName"] ?? "signatures-certificate.pfx"), builder.Configuration["HttpSignatures:PfxPass"], X509KeyStorageFlags.MachineKeySet);
#else
var httpSignatureCertificate = new X509Certificate2(Path.Combine(webHostEnvironment.ContentRootPath, configuration["IdentityServer:SigningPfxFile"] ?? string.Empty), configuration["IdentityServer:SigningPfxPass"], X509KeyStorageFlags.MachineKeySet);
#endif
builder.Services.AddHttpSignatures(options => {
    options.MapPath("/payments", HeaderFieldNames.RequestTarget, HeaderFieldNames.Created, HttpDigest.HTTPHeaderName, "x-response-id");
    options.MapPath("/payments/execute", HeaderFieldNames.RequestTarget, HeaderFieldNames.Created, HttpDigest.HTTPHeaderName, "x-response-id");
})
.AddSigningCredential(httpSignatureCertificate);

var app = builder.Build();

app.UseHttpsRedirection();
app.UseHttpSignatures();
app.UseSwaggerUI(x => {
    x.SwaggerEndpoint($"/swagger/cert/swagger.json", "cert");
});

app.MapSwagger();

app.MapCertificateStore();

app.Run();