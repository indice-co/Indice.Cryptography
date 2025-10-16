# Indice.Cryptography.AspNetCore

ASP.NET Core extensions for the Indice.Cryptography library, providing certificate server capabilities and HTTP message signing middleware for web applications.

## Features

- **Certificate Server**: Complete certificate management server with REST API endpoints
- **HTTP Message Signing**: Middleware for automatic HTTP signature generation and validation
- **Entity Framework Integration**: Database storage for certificates and revocation lists
- **RESTful Certificate API**: Full CRUD operations for certificate lifecycle management
- **Certificate Revocation Lists (CRL)**: Generate and serve standards-compliant CRL endpoints
- **Swagger/OpenAPI Integration**: Auto-generated API documentation

## Installation

Install the package via NuGet Package Manager:

```powershell
Install-Package Indice.Cryptography.AspNetCore
```

Or via .NET CLI:

```bash
dotnet add package Indice.Cryptography.AspNetCore
```

## Quick Start

### Basic Setup

```csharp
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Add certificate server
builder.Services.AddCertificateServer(builder.Environment, options => {
    options.IssuerDomain = "ca.example.com";
    options.PfxPassphrase = "your-secure-password";
});

// Add HTTP signatures
builder.Services.AddHttpSignatures(options => {
    options.MapPath("/api/payments", "x-request-id", "(created)", "digest");
})
.AddSigningCredential(certificate);

var app = builder.Build();

// Configure middleware
app.UseHttpSignatures();

// Map certificate endpoints
app.MapCertificateStore();

app.Run();
```

## Certificate Server

### Configuration

```csharp
builder.Services.AddCertificateServer(environment, options => {
    options.IssuerDomain = "ca.example.com";
    options.PfxPassphrase = "secure-ca-password";
    options.Path = "/custom/cert/storage/path"; // Optional
    
    // Add Entity Framework storage
    options.AddEntityFrameworkStore(storeOptions => {
        storeOptions.DefaultSchema = "certificates";
        storeOptions.ConfigureDbContext = dbBuilder => {
            dbBuilder.UseSqlServer(connectionString);
        };
    });
});
```

### Certificate API Endpoints

The certificate server automatically exposes the following REST endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/.certificates/ca.cer` | Download CA certificate |
| `POST` | `/.certificates` | Create new certificate |
| `GET` | `/.certificates/{keyId}.{format}` | Export certificate |
| `PUT` | `/.certificates/{keyId}/revoke` | Revoke certificate |
| `GET` | `/.certificates` | List certificates |
| `GET` | `/.certificates/revoked.crl` | Certificate revocation list |

### Creating Certificates via API

```csharp
// POST /.certificates
var request = new Psd2CertificateRequest
{
    City = "Athens",
    State = "Attiki",
    CountryCode = "GR",
    Organization = "Example Bank",
    OrganizationUnit = "IT",
    CommonName = "api.example-bank.com",
    AuthorityId = "BOG",
    AuthorityName = "Bank of Greece",
    AuthorizationNumber = "123456789",
    ValidityInDays = 365,
    Roles = new Psd2CertificateRequest.Psd2RoleFlags
    {
        Aisp = true,
        Pisp = true,
        Aspsp = false,
        Piisp = false
    },
    QcType = QcTypeIdentifiers.Web
};

// The API will return a CertificateDetails object with metadata
```

### Exporting Certificates

```csharp
// Export as different formats
GET /.certificates/{keyId}.cer     // X.509 certificate (DER)
GET /.certificates/{keyId}.pem     // PEM format
GET /.certificates/{keyId}.pfx     // PKCS#12 with private key (requires password)
```

## HTTP Message Signing

### Middleware Configuration

```csharp
builder.Services.AddHttpSignatures(options => {
    // Configure paths and headers to include in signatures
    options.MapPath("/api/payments", 
        HeaderFieldNames.RequestTarget,
        HeaderFieldNames.Created,
        HttpDigest.HTTPHeaderName,
        "x-request-id");
    
    options.MapPath("/api/accounts/*", 
        HeaderFieldNames.RequestTarget,
        HeaderFieldNames.Created);
    
    // Global settings
    options.RequestCreatedHeaderName = "x-created";
    options.ForwardedPathHeaderName = "x-forwarded-path";
    options.ResponseSigning = true; // Sign responses
})
.AddSigningCredential(certificate);

// Apply middleware (must be early in pipeline)
app.UseHttpSignatures();
```

### Header Configuration

The middleware supports various HTTP signature headers:

```csharp
// Special header field names
HeaderFieldNames.RequestTarget  // "(request-target)"
HeaderFieldNames.Created       // "(created)"
HeaderFieldNames.Expires       // "(expires)"

// Standard headers
HttpDigest.HTTPHeaderName      // "digest"
"authorization"
"content-type"
"x-request-id"
// ... any custom headers
```

### Signature Validation

```csharp
// The middleware automatically validates incoming signatures
// You can also manually validate:

var signature = HttpSignature.Parse(signatureHeader);
var isValid = signature.Validate(publicKey, httpRequest);
```

## Entity Framework Integration

### Database Schema

The library provides Entity Framework integration for persistent storage:

```csharp
options.AddEntityFrameworkStore(storeOptions => {
    storeOptions.DefaultSchema = "cert";
    storeOptions.ConfigureDbContext = builder => {
        builder.UseSqlServer(connectionString);
        // Or any other EF Core provider
    };
});
```

### Database Models

The database stores:
- **Certificates**: Full certificate data with metadata
- **Revocation information**: Revoked certificate tracking
- **CA certificates**: Issuer certificate storage

### Migration

```bash
# Add migration for certificate schema
dotnet ef migrations add CertificateSchema
dotnet ef database update
```

## Background Services

### Certificate Bootstrapping

The library includes a background service that automatically:
- Creates a root CA certificate if none exists
- Generates initial certificate infrastructure
- Maintains certificate storage

```csharp
// Automatically registered when certificate store is configured
services.AddHostedService<CertificatesBackgroundService>();
```

## Advanced Configuration

### Custom Certificate Storage

```csharp
// Implement custom storage
public class CustomCertificateStore : ICertificatesStore
{
    public async Task<CertificateDetails> Add(X509Certificate2 certificate, Psd2CertificateRequest request)
    {
        // Custom storage logic
    }
    
    // ... implement other methods
}

// Register custom store
services.AddTransient<ICertificatesStore, CustomCertificateStore>();
```

### Custom HTTP Signature Validation

```csharp
// Custom validation key store
public class CustomValidationKeysStore : IHttpValidationKeysStore
{
    public Task<SecurityKey[]> GetValidationKeysAsync()
    {
        // Return public keys for signature validation
    }
}

services.AddSingleton<IHttpValidationKeysStore, CustomValidationKeysStore>();
```

### Custom Signing Credentials

```csharp
// Custom signing credential store
public class CustomSigningCredentialsStore : IHttpSigningCredentialsStore
{
    public Task<SigningCredentials> GetSigningCredentialsAsync()
    {
        // Return signing credentials
    }
}

services.AddSingleton<IHttpSigningCredentialsStore, CustomSigningCredentialsStore>();
```

## Swagger/OpenAPI Integration

The certificate endpoints are automatically documented:

```csharp
builder.Services.AddSwaggerGen(options => {
    options.SwaggerDoc("cert", new OpenApiInfo 
    { 
        Title = "Certificate API", 
        Version = "v1" 
    });
    
    // Include XML comments for better documentation
    var xmlPath = Path.Combine(AppContext.BaseDirectory, "YourApp.xml");
    options.IncludeXmlComments(xmlPath);
});

app.UseSwaggerUI(options => {
    options.SwaggerEndpoint("/swagger/cert/swagger.json", "Certificate API");
});
```

## Security Considerations

### Certificate Storage Security

- Store CA private keys securely
- Use strong passphrases for PFX files
- Implement proper access controls for certificate endpoints
- Regular backup of certificate store

### HTTP Signature Security

- Use strong RSA keys (minimum 2048 bits)
- Include timestamp headers to prevent replay attacks
- Validate signature expiration
- Implement proper key rotation

### Production Deployment

```csharp
// Production configuration
if (app.Environment.IsProduction())
{
    // Use production certificate storage
    options.Path = "/secure/certificate/storage";
    
    // Enable HTTPS only
    app.UseHttpsRedirection();
    
    // Add security headers
    app.UseHsts();
}
```

## Monitoring and Logging

The library integrates with ASP.NET Core logging:

```csharp
// Configure logging
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(LogLevel.Information);

// The library will log:
// - Certificate creation and revocation
// - HTTP signature validation results
// - CA operations
// - Background service activities
```

## Testing

### Test Configuration

```csharp
// In test projects
var services = new ServiceCollection();
services.AddCertificateServer(environment, options => {
    options.IssuerDomain = "test-ca.local";
    options.Path = Path.GetTempPath();
});

services.AddHttpSignatures()
    .AddSigningCredential(testCertificate);

var serviceProvider = services.BuildServiceProvider();
```

### Integration Testing

```csharp
var factory = new WebApplicationFactory<Program>();
var client = factory.CreateClient();

// Test certificate creation
var response = await client.PostAsJsonAsync("/.certificates", request);
response.Should().BeSuccessful();

// Test signature validation
var signedRequest = new HttpRequestMessage(HttpMethod.Post, "/api/payments");
// Add signature headers...
var result = await client.SendAsync(signedRequest);
```

## Dependencies

- **ASP.NET Core 8.0+** - Web framework
- **Entity Framework Core 8.0+** - Database integration  
- **Indice.Cryptography** - Core cryptography functionality
- **Microsoft.OpenApi** - OpenAPI/Swagger support
- **System.Text.Json** - JSON serialization

## Migration from Previous Versions

### Breaking Changes in 2.x

- Updated to .NET 8.0 minimum
- Changed certificate storage interface
- Updated HTTP signature header format

### Migration Steps

1. Update target framework to .NET 8.0+
2. Update service registration calls
3. Update database schema if using EF
4. Test HTTP signature compatibility

## Contributing

Contributions are welcome! Please:

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Submit pull requests to the main repository

## License

This project is licensed under the MIT License.

## Support

For questions and support:
- Check the [GitHub Issues](https://github.com/indice-co/Indice.Cryptography/issues)
- Review the sample applications
- Consult the main documentation