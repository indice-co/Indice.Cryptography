[![Nuget](https://img.shields.io/nuget/vpre/Indice.Cryptography?logo=nuget)](https://www.nuget.org/packages/Indice.Cryptography/)
# Indice.Cryptography  ![alt text](icon/icon-64.png "Indice logo")
A comprehensive .NET cryptography library focused on PSD2 compliance, X.509 certificate management, and HTTP message signing.

## Features

- **PSD2 Compliance**: Complete support for Payment Services Directive 2 requirements
- **X.509 Certificate Management**: Create, validate, and manage certificates with European Qualified Certificate extensions
- **HTTP Message Signing**: Implement HTTP signature-based authentication
- **Certificate Authority**: Create and manage custom Certificate Authorities
- **ASN.1/DER Encoding**: Low-level cryptographic primitives and certificate extensions

## Installation

Install the package via NuGet Package Manager:

```powershell
Install-Package Indice.Cryptography
```

Or via .NET CLI:

```bash
dotnet add package Indice.Cryptography
```

## Quick Start

### Creating PSD2 Certificates

```csharp
using Indice.Cryptography;
using Indice.Cryptography.X509Certificates;

var certificateManager = new CertificateManager();

// Create a PSD2 certificate request
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
        Aisp = true,  // Account Information Service Provider
        Pisp = true,  // Payment Initiation Service Provider
        Aspsp = true, // Account Servicing Payment Service Provider
        Piisp = false // Payment Instrument Issuer Service Provider
    },
    QcType = QcTypeIdentifiers.Web
};

// Generate the certificate
var certificate = certificateManager.CreateQualifiedCertificate(
    request, 
    "ca.example.com", 
    issuer: null, // Will create CA on-the-fly
    out RSA privateKey
);
```

### HTTP Message Signing

```csharp
using Indice.Cryptography.Tokens.HttpMessageSigning;

// Configure HTTP signatures
services.AddHttpSignatures(options => {
    options.MapPath("/payments", 
        HeaderFieldNames.RequestTarget, 
        HeaderFieldNames.Created, 
        HttpDigest.HTTPHeaderName, 
        "x-response-id");
})
.AddSigningCredential(certificate);

// Use in your application
app.UseHttpSignatures();
```

### Certificate Validation

```csharp
using Indice.Cryptography.Validation;

var validator = new Psd2ClientCertificateValidator();
var isValid = await validator.ValidateAsync(certificate, context);
```

## Key Components

### Certificate Management

- **CertificateManager**: Core class for certificate creation and management
- **Psd2CertificateRequest**: Model for PSD2-compliant certificate requests
- **SubjectBuilder**: Fluent API for building X.509 certificate subjects

### X.509 Extensions

The library includes comprehensive support for European Qualified Certificate extensions:

- **QualifiedCertificateStatementsExtension**: QC statements per ETSI EN 319 412-5
- **AuthorityInformationAccessExtension**: Authority information access points
- **CRLDistributionPointsExtension**: Certificate revocation list distribution
- **CABForumOrganizationIdentifierExtension**: Organization identifier extensions
- **CertificatePoliciesExtension**: Certificate policy information

### PSD2 Specific Features

- **Psd2Attributes**: PSD2 role and authority information
- **NCAId**: National Competent Authority identifiers
- **QcTypeIdentifiers**: Qualified certificate type identifiers (QWAC, QSEAL, etc.)

### HTTP Message Signing

- **HttpSignature**: HTTP signature generation and validation
- **HttpDigest**: HTTP digest calculation for message integrity
- **HttpSignatureDelegatingHandler**: HTTP client handler for automatic signing
- **HttpSignatureSecurityToken**: Security token for HTTP signatures

## Configuration Examples

### ASP.NET Core Integration

```csharp
// In Program.cs or Startup.cs
services.AddCertificateServer(environment, options => {
    options.IssuerDomain = "ca.example.com";
    options.AddEntityFrameworkStore(sqlOptions => {
        sqlOptions.ConfigureDbContext = builder => {
            builder.UseSqlServer(connectionString);
        };
    });
});

// Configure HTTP signatures for specific endpoints
services.AddHttpSignatures(options => {
    options.MapPath("/api/payments/*", 
        HeaderFieldNames.RequestTarget,
        HeaderFieldNames.Created,
        HttpDigest.HTTPHeaderName);
})
.AddSigningCredential(certificate);
```

### Creating Custom Certificate Authorities

```csharp
var certificateManager = new CertificateManager();

// Create a root CA certificate
var rootCA = certificateManager.CreateRootCACertificate(
    "Root CA Example", 
    diagnostics: null
);

// Use the CA to sign other certificates
var clientCertificate = certificateManager.CreateQualifiedCertificate(
    request, 
    issuerDomain: "ca.example.com",
    issuer: rootCA,
    out RSA privateKey
);
```

## Certificate Extensions

### Qualified Certificate Statements

```csharp
var qcStatements = new QualifiedCertificateStatementsExtension(
    isCompliant: true,
    limit: new QcMonetaryValue { CurrencyCode = "EUR", Value = 500000 },
    retentionPeriod: 7,
    isQSCD: true,
    pdsLocations: new[] { 
        new PdsLocation { 
            Language = "EN", 
            Url = "https://example.com/pds" 
        } 
    },
    type: QcTypeIdentifiers.Web,
    psd2: new Psd2Attributes
    {
        AuthorityName = "National Bank",
        AuthorizationId = new NCAId("PSD", "GR", "NBG", "123456"),
        HasAccountInformation = true,
        HasPaymentInitiation = true
    },
    critical: false
);
```

### Authority Information Access

```csharp
var authorityInfo = new AuthorityInformationAccessExtension(new[] {
    new AccessDescription
    {
        AccessMethod = AccessDescription.AccessMethodType.CertificationAuthorityIssuer,
        AccessLocation = "http://ca.example.com/ca.cer"
    },
    new AccessDescription
    {
        AccessMethod = AccessDescription.AccessMethodType.OnlineCertificateStatusProtocol,
        AccessLocation = "http://ocsp.example.com"
    }
}, critical: false);
```

## PSD2 Role Mapping

The library supports all PSD2 payment service provider roles:

| Role Code | Description | Property |
|-----------|-------------|----------|
| PSP_AS | Account Servicing | `HasAccountServicing` |
| PSP_PI | Payment Initiation | `HasPaymentInitiation` |
| PSP_AI | Account Information | `HasAccountInformation` |
| PSP_IC | Payment Instrument Issuing | `HasIssuingOfCardBasedPaymentInstruments` |

## HTTP Signature Algorithm

The library implements the HTTP Signatures draft specification for securing HTTP messages:

```csharp
// Signature string format
var signatureString = $"{HeaderFieldNames.RequestTarget}: post /payments\n" +
                     $"{HeaderFieldNames.Created}: 1618302811\n" +
                     $"{HttpDigest.HTTPHeaderName}: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=";

// Generate signature
var signature = HttpSignature.GenerateSignature(signatureString, privateKey);
```

## Advanced Usage

### Custom Subject Building

```csharp
var subject = new SubjectBuilder()
    .AddCommonName("api.bank.com")
    .AddOrganization("Example Bank", "IT Department")
    .AddLocation("GR", "Attiki", "Athens")
    .AddEmail("admin@bank.com")
    .AddOrganizationIdentifier(new NCAId("PSD", "GR", "BOG", "123456"))
    .Build();
```

### Certificate Revocation Lists

```csharp
var crlExtension = new CRLDistributionPointsExtension(new[] {
    new CRLDistributionPoint 
    { 
        FullName = new[] { "http://crl.example.com/revoked.crl" } 
    }
}, critical: false);
```

## Dependencies

- **.NET 8.0** or later
- **DerConverter** - ASN.1 DER encoding/decoding
- **PemUtils** - PEM format utilities  
- **System.IdentityModel.Tokens.Jwt** - JWT token handling
- **System.Security.Cryptography.*** - Core cryptography APIs

## Standards Compliance

This library implements the following standards:

- **RFC 5280** - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile
- **RFC 3739** - Internet X.509 Public Key Infrastructure: Qualified Certificates Profile  
- **ETSI EN 319 412-5** - Electronic Signatures and Infrastructures (ESI); Certificate Profiles; Part 5: QCStatements in certificates
- **ETSI TS 119 495** - Electronic Signatures and Infrastructures (ESI); Sector Specific Requirements; PSD2 sector requirements for eIDAS certificates
- **PSD2 Directive (EU) 2015/2366** - Payment Services Directive 2
- **HTTP Signatures Draft** - Signing HTTP Messages

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the terms specified in the project license file (MIT).

## Support

For questions and support, please check the project's issue tracker or contact the maintainers.
