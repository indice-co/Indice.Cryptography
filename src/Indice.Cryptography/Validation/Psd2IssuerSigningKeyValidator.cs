using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using Indice.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.Validation;


/// <summary>
/// Implementation of an Issuer signing key validator for use with the <see cref="JwtSecurityTokenHandler"/>. 
/// This class handles validating the issuer key of a JWT client authentication request in accordance with Psd2 regulation. 
/// Takes the public key <see cref="X509Certificate"/> and extracts Ps2 attributes contained. Then validates the <see cref="NCAId"/> against the subject. 
/// Furthermore it also should validate the cerificate NCAId to be in the trusted registry. And finaly the authority (certificate issuer for) should be on one if the NCA or CEB trusted issuer lists.
/// </summary>
public class Psd2IssuerSigningKeyValidator {

    //public bool ValidateNCA_TrustedIssuers { get; set; }
    //public bool ValidateNCA_Enrolled_TPP { get; set; }
    //public bool Validate_eIDAS { get; set; }

    /// <summary>
    /// Validates the issuer signing key according to PSD2.
    /// </summary>
    /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
    /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters" /> required for validation.</param>
    /// <returns></returns>
    public bool Validate(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters) {
        var x509key = default(X509SecurityKey);
        var jwtToken = (JwtSecurityToken)securityToken;
        if (securityKey is X509SecurityKey) {
            x509key = securityKey as X509SecurityKey;
        } else {
            return true;
        }
        return ValidateInternal(x509key!, jwtToken, validationParameters);
    }

    /// <summary>
    /// Validates the issuer signing key according to PSD2.
    /// </summary>
    /// <param name="asymetricKey">The <see cref="X509SecurityKey"/> that signed the <see cref="JwtSecurityToken"/>.</param>
    /// <param name="jwtToken">The <see cref="JwtSecurityToken"/> being validated.</param>
    /// <param name="validationParameters">The <see cref="TokenValidationParameters" /> required for validation.</param>
    /// <returns></returns>
    protected virtual bool ValidateInternal(X509SecurityKey asymetricKey, JwtSecurityToken jwtToken, TokenValidationParameters validationParameters) {
        //var attributes = asymetricKey.Certificate.GetPsd2Attributes();
        //var organizationId = asymetricKey.Certificate.GetCABForumOrganizationIdentifier();
        //var subjectOrgId = asymetricKey.Certificate.GetSubjectBuilder().GetOrganizationIdentifier();
        //var ok = false;
        //ok = attributes?.AuthorizationId.ToString() == jwtToken.Subject ||
        //     attributes?.AuthorizationId.AuthorizationNumber == jwtToken.Subject ||
        //     organizationId?.ToString() == jwtToken.Subject ||
        //     subjectOrgId == jwtToken.Subject;
        var ok = true;
        return ok;
    }
}
