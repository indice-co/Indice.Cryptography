using System.Text;
using Indice.Cryptography.X509Certificates;

namespace System.Security.Cryptography.X509Certificates;

/// <summary>
/// Extension methods and utilities related to certificate generation and validation
/// </summary>
public static class CertificatesExtensions
{
    /// <summary>
    /// Export a certificate to a PEM format string
    /// </summary>
    /// <param name="cert">The certificate to export</param>
    /// <returns>A PEM encoded string</returns>
    [Obsolete("Use ExportCertificatePem instead.")]
    public static string ExportToPEM(this X509Certificate2 cert) {
        return MakePem(cert.Export(X509ContentType.Cert), "CERTIFICATE", insertLineBreaks: true);
    }

    private static string MakePem(byte[] ber, string header, bool insertLineBreaks = false) {
        StringBuilder builder = new StringBuilder("-----BEGIN ");
        builder.Append(header);
        builder.AppendLine("-----");

        string base64 = Convert.ToBase64String(ber, insertLineBreaks ? Base64FormattingOptions.InsertLineBreaks : Base64FormattingOptions.None);
        int offset = 0;
        const int LineLength = 64;

        while (offset < base64.Length) {
            int lineEnd = Math.Min(offset + LineLength, base64.Length);
            builder.AppendLine(base64.Substring(offset, lineEnd - offset));
            offset = lineEnd;
        }

        builder.Append("-----END ");
        builder.Append(header);
        builder.AppendLine("-----");
        return builder.ToString();
    }


    /// <summary>
    /// Export the public key to a PEM format string
    /// </summary>
    /// <param name="rsa">the RSA key</param>
    /// <returns>A PEM encoded string</returns>
    public static string ToSubjectPublicKeyInfo(this RSA rsa) {
        return rsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>
    /// Export the private  key to a PEM format string
    /// </summary>
    /// <param name="rsa">the RSA key</param>
    /// <returns>A PEM encoded string</returns>
    public static string ToRSAPrivateKey(this RSA rsa) {
        return rsa.ExportRSAPrivateKeyPem();
    }
    
    /// <summary>
    /// Import an RSA key from PEM format string
    /// </summary>
    /// <param name="pem">the RSA key in PEM format</param>
    /// <returns>the RSA key parameters</returns>
    public static RSAParameters ReadAsRSAKey(this string pem) {
        using (var rsa = RSA.Create()) {
            rsa.ImportFromPem(pem);
            return rsa.ExportParameters(includePrivateParameters: true);
        }
    }

    /// <summary>
    /// Find the issuer certificate. 
    /// First checks if the leaf certificate's Subject and Issuer fields are not the same. 
    /// Otherwise, the certificate is the issuer (self-signed certificate)
    /// If different it instatniates a X509Chain object and passes leaf certificate to X509Chain.Build method.Examine ChainElements property (a collection) and element at index 1 is the issuer.
    /// </summary>
    /// <param name="leafCert"></param>
    /// <returns></returns>
    public static X509Certificate2? GetIssuer(X509Certificate2 leafCert) {
        if (leafCert.Subject == leafCert.Issuer) { return leafCert; }
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.Build(leafCert);
        X509Certificate2? issuer = null;
        if (chain.ChainElements.Count > 1) {
            issuer = chain.ChainElements[1].Certificate;
        }
        chain.Reset();
        return issuer;
    }

    /// <summary>
    /// Find the ETSI QualifiedExtensions extension and extract all information.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static QualifiedCertificateStatements? GetQualifiedCertificateStatements(this X509Certificate2 cert) {
        var statements = default(QualifiedCertificateStatements);
        var extension = cert.Extensions[QualifiedCertificateStatementsExtension.Oid_QC_Statements];
        if (extension != null) {
            var qcStatements = new QualifiedCertificateStatementsExtension(extension, extension.Critical);
            statements = qcStatements.Statements;
        }
        return statements;
    }

    /// <summary>
    /// Find the SubjectKeyIdentifier extension and extract the key id.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static string? GetSubjectKeyIdentifier(this X509Certificate2 cert) {
        string? keyid = null;
        var extension = cert.Extensions[AuthorityKeyIdentifierExtension.Oid_SubjectKeyIdentifier] as X509SubjectKeyIdentifierExtension;
        if (extension != null) {
            keyid = extension.SubjectKeyIdentifier;
        }
        return keyid;
    }
    
    /// <summary>
    /// Find the KeyIdentifier of the issuer certificate.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static string? GetAuthorityKeyIdentifier(this X509Certificate2 cert) {
        string? keyid = null;
        var extension = cert.Extensions[AuthorityKeyIdentifierExtension.Oid_AuthorityKeyIdentifier];
        if (extension != null) {
            keyid = new AuthorityKeyIdentifierExtension(extension, extension.Critical).AuthorityKeyIdentifier;
        }
        return keyid;
    }

    /// <summary>
    /// Find the AIA descriptions. Authority Information Access Extension
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static AccessDescription[]? GetAuthorityInformationAccess(this X509Certificate2 cert) {
        var accessDescriptions = default(AccessDescription[]);
        var extension = cert.Extensions[AuthorityInformationAccessExtension.Oid_AuthorityInformationAccess];
        if (extension != null) {
            accessDescriptions = new AuthorityInformationAccessExtension(extension, extension.Critical).AccessDescriptions;
        }
        return accessDescriptions;
    }

    /// <summary>
    /// Certificate Policies Extension.
    /// This extension lists certificate policies, recognized by the issuing CA, that apply to the certificate, 
    /// together with optional qualifier information pertaining to these certificate policies. 
    /// Typically, different certificate policies will relate to different applications which may use the certified key.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static PolicyInformation[]? GetCertificatePolicies(this X509Certificate2 cert) {
        var policies = default(PolicyInformation[]);
        var extension = cert.Extensions[CertificatePoliciesExtension.Oid_CertificatePolicies];
        if (extension != null) {
            policies = new CertificatePoliciesExtension(extension, extension.Critical).Policies;
        }
        return policies;
    }

    /// <summary>
    /// Find the CRL distribution points.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static CRLDistributionPoint[]? GetCRLDistributionPoints(this X509Certificate2 cert) {
        var points = default(CRLDistributionPoint[]);
        var extension = cert.Extensions[CRLDistributionPointsExtension.Oid_CRLDistributionPoints];
        if (extension != null) {
            points = new CRLDistributionPointsExtension(extension, extension.Critical).DistributionPoints;
        }
        return points;
    }

    /// <summary>
    /// Find the Organization Identifier. PSD2 CA/Browser Forum OrganizationIdentifier
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static CABForumOrganizationIdentifier? GetCABForumOrganizationIdentifier(this X509Certificate2 cert) {
        var org = default(CABForumOrganizationIdentifier);
        var extension = cert.Extensions[CABForumOrganizationIdentifierExtension.Oid_CabForumOrganizationIdentifier];
        if (extension != null) {
            org = new CABForumOrganizationIdentifierExtension(extension, extension.Critical).OrganizationIdentifier;
        }
        return org;
    }

    /// <summary>
    /// Initialized an instance of the <see cref="SubjectBuilder"/> using the certificate <seealso cref="X509Certificate2.SubjectName"/>
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static SubjectBuilder GetSubjectBuilder(this X509Certificate2 cert) {
        return SubjectBuilder.Parse(cert.Subject);
    }

    /// <summary>
    /// Find the KeyIdentifier of the issuer certificate.
    /// </summary>
    /// <param name="cert"></param>
    /// <returns></returns>
    public static bool IsCertificateAuthority(this X509Certificate2 cert) {
        var extension = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
        return extension?.CertificateAuthority == true;
    }
}
