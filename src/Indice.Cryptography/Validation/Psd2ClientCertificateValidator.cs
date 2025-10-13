using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Indice.Cryptography.X509Certificates;

namespace Indice.Cryptography.Validation;

/// <summary>
/// When a cerificate is presented to be associated with a PSD2 third party provider it must be first validated. 
/// 1. Check the AuthorityKeyIdentifier against NCA trusted issuer list for the country where the TPP operates.
/// 2. Check the AuthorityInformationAccess extension in order to download the CA issuing certificate.
/// 3. Check the CRLDistribution points to find the url of the Certificate Revocation List and check if this certificate has been revoked (check the serialnumber of this cert may be in the list).
/// </summary>
public class Psd2ClientCertificateValidator
{
    /// <summary>
    /// Constructs the class.
    /// </summary>
    public Psd2ClientCertificateValidator() {

    }

    /// <summary>
    /// Validate the <see cref="X509Certificate2"/> for PSD2 compliance.
    /// </summary>
    /// <param name="certificate"></param>
    /// <param name="type">QC Type identifier. qSeal, qSign, Web. If passed null checks any of the valid ones</param>
    /// <param name="errors"></param>
    public bool Validate(X509Certificate2 certificate, X509Certificates.QcTypeIdentifiers? type, out IEnumerable<string> errors) {
        var errorList = new List<string>();
        errors = errorList;
        var authorityKeyId = certificate.GetAuthorityKeyIdentifier();

        if (string.IsNullOrEmpty(authorityKeyId)) {
            errorList.Add("Missing authority Key Identifier extension");
        }
        var qcStatements = certificate.GetQualifiedCertificateStatements();
        if (qcStatements == null) {
            errorList.Add("Missing the QcStatements X509Certivicate extension");
        } else {
            if (!qcStatements.IsCompliant) 
                errorList.Add($"Although the certificate has the QcStatements X509Certivicate extension it is not a compliant \"European Qualified Certificate\". ");
            if (qcStatements?.Psd2Type == null)
                errorList.Add("This is not a valid QWAC or QCseal. Missing the PSD2 type QcStatement");
            if (type.HasValue && type.Value != qcStatements!.Type) { 
                errorList.Add($"{qcStatements.Type} is not a valid QcTypeIdentifier for the current use of this certificate. Expected option {type}");
            } else if ((int)qcStatements!.Type < 0 && 3 < (int)qcStatements.Type) {
                errorList.Add($"{qcStatements.Type} is not a valid QcTypeIdentifier. Valid options include {QcTypeIdentifiers.Web}, {QcTypeIdentifiers.eSeal} and {QcTypeIdentifiers.eSign}");
            }
            if (!qcStatements.Psd2Type.Roles.Any()) {
                errorList.Add("There are no roles defined in this certificate");
            }
            //if (!qcStatements.Psd2Type.AuthorizationId.IsValid) {
            //    errorList.Add($"The NCAId is not in a valid format {qcStatements.Psd2Type.AuthorizationId}");
            //}
        }
        var accessDescriptions = certificate.GetAuthorityInformationAccess();
        if (accessDescriptions == null || !accessDescriptions.Any()) {
            errorList.Add($"There is no Authority Information Access extension inside the certificate.");
        }
        var policies = certificate.GetCertificatePolicies();
        if (policies == null || !policies.Any(x => x.IsEUQualifiedCertificate)) {
            errorList.Add($"There is no Certificate Policy that identifies the current certificate as EU Qualified. There should be one in every eIDAs cert. Acceptable policy identifiers include: QCP-n, QCP-l, QCP-n-qscd, QCP-l-qscd, QCP-w");
        }
        var crlDistributionPoints = certificate.GetCRLDistributionPoints();
        if (crlDistributionPoints == null || !crlDistributionPoints.Any()) {
            errorList.Add($"There is no CRL distribution points extension inside the certificate.");
        }
        var authorizationId = qcStatements!.Psd2Type.AuthorizationId;
        var organizationId = certificate.GetCABForumOrganizationIdentifier();
        var subjectOrgId = certificate.GetSubjectBuilder().GetOrganizationIdentifier();
        if (string.IsNullOrEmpty(subjectOrgId)) {
            errorList.Add("The subject must contain the Organization Identifier as defined in PSD2 by the 2.5.4.97 Oid");
        }
        if (organizationId == null) {
            errorList.Add("There is no CA/Browser Forum OrganizationIdentifier extension inside the certificate. Oid 2.23.140.3.1");
        }
        if (!string.IsNullOrEmpty(subjectOrgId) && organizationId != null) {
            if (!NCAId.TryParse(organizationId.ToString(), out var id) || !id.IsValid) {
                errorList.Add($"The organizationId inside the CA/Browser Forum OrganizationIdentifier has an invalid format. {organizationId}");
            } else if (!id.Equals(subjectOrgId)) { 
                errorList.Add($"The organizationId inside the CA/Browser Forum OrganizationIdentifier is not the same with the one in the subject, {organizationId} != {subjectOrgId}");
            }
        }
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.Build(certificate);
        X509Certificate2? issuer = null;
        if (chain.ChainElements.Count > 1) {
            issuer = chain.ChainElements[1].Certificate;
        }
        chain.Reset();

        return errorList.Count == 0;
    }
}
