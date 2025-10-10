using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DerConverter;
using DerConverter.Asn;
using DerConverter.Asn.KnownTypes;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Certificate Policies Extension.
/// This extension lists certificate policies, recognized by the issuing CA, that apply to the certificate, 
/// together with optional qualifier information pertaining to these certificate policies. 
/// Typically, different certificate policies will relate to different applications which may use the certified key.
/// </summary>
/// <remarks>
/// id-ce-certificatePolicies OBJECT IDENTIFIER ::=  { id-ce 32 }
///
/// anyPolicy OBJECT IDENTIFIER ::= { id-ce-certificatePolicies 0 }
///
/// certificatePolicies::= SEQUENCE SIZE(1..MAX) OF PolicyInformation
///
/// PolicyInformation ::= SEQUENCE {
///     policyIdentifier   CertPolicyId,
///     policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///                               PolicyQualifierInfo OPTIONAL }
///
/// CertPolicyId::= OBJECT IDENTIFIER
///
/// PolicyQualifierInfo ::= SEQUENCE {
///     policyQualifierId PolicyQualifierId,
///     qualifier          ANY DEFINED BY policyQualifierId }
///
/// -- policyQualifierIds for Internet policy qualifiers
///
///
/// id-qt         OBJECT IDENTIFIER::=  { id-pkix 2 }
/// id-qt-cps     OBJECT IDENTIFIER::=  { id-qt 1 }
/// id-qt-unotice OBJECT IDENTIFIER::=  { id-qt 2 }
///
/// PolicyQualifierId ::= OBJECT IDENTIFIER(id - qt - cps | id - qt - unotice)
///
/// Qualifier ::= CHOICE {
///     cPSuri           CPSuri,
///     userNotice       UserNotice }
///
/// CPSuri::= IA5String
///
/// UserNotice::= SEQUENCE {
///     noticeRef        NoticeReference OPTIONAL,
///     explicitText     DisplayText OPTIONAL }
///
/// NoticeReference::= SEQUENCE {
///     organization     DisplayText,
///     noticeNumbers    SEQUENCE OF INTEGER }
///
/// DisplayText::= CHOICE {
///     ia5String        IA5String      (SIZE (1..200)),
///     visibleString    VisibleString  (SIZE (1..200)),
///     bmpString        BMPString      (SIZE (1..200)),
///     utf8String       UTF8String     (SIZE (1..200)) }
/// </remarks>
public class CertificatePoliciesExtension : X509Extension
{
    //https://tools.ietf.org/html/rfc5280
    /// <summary>
    /// Certificate Policies Oid (X509 v2)
    /// </summary>
    public const string Oid_CertificatePolicies = "2.5.29.32";

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="policies"></param>
    /// <param name="critical"></param>
    public CertificatePoliciesExtension(PolicyInformation[] policies, bool critical) {
        Oid = new Oid(Oid_CertificatePolicies, "Certificate Policies");
        Critical = critical;
        RawData = DerConvert.Encode(new CertificatePolicies(policies)).ToArray();
        _Policies = policies;
        _decoded = true;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public CertificatePoliciesExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {

    }

    private bool _decoded = false;
    private PolicyInformation[] _Policies;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public PolicyInformation[] Policies {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _Policies;
        }
    }

    /// <summary>
    /// Copies the extension properties of the specified System.Security.Cryptography.AsnEncodedData object.
    /// </summary>
    /// <param name="asnEncodedData">The System.Security.Cryptography.AsnEncodedData to be copied.</param>
    public override void CopyFrom(AsnEncodedData asnEncodedData) {
        base.CopyFrom(asnEncodedData);
        _decoded = false;
    }

    private void DecodeExtension() {
        var sequence = DerConvert.Decode(RawData) as DerAsnSequence;
        _Policies = new CertificatePolicies(sequence.Value).Extract();
        _decoded = true;
    }
}

/// <summary>
/// Certificate Policies Der ASN.1 sequense
/// </summary>
public class CertificatePolicies : DerAsnSequence
{
    /// <summary>
    /// Constructs the <see cref="CertificatePolicies"/> from <see cref="List{PolicyInformation}"/>.
    /// </summary>
    /// <param name="policies"></param>
    public CertificatePolicies(PolicyInformation[] policies) : base(new DerAsnType[0]) {
        var list = new List<DerAsnSequence>();
        foreach (var policy in policies) {
            var definition = new List<DerAsnType>();
            if (policy.PolicyIdentifier != null) {
                var id = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, policy.PolicyIdentifier.OidToArray());
                definition.Add(id);
            }
            if (policy.PolicyQualifiers?.Count > 0) {
                var definitionQualifiers = new List<DerAsnType>();
                foreach (var qualifier in policy.PolicyQualifiers) {
                    var qualifierId = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, qualifier.Identifier.OidToArray());
                    var qualifierValue = default(DerAsnType);
                    if (qualifier.Type == PolicyQualifierType.UserNotice) {
                        var noticeSequence = new List<DerAsnType>();
                        if (qualifier.UserNotice?.Reference != null) {
                            noticeSequence.Add(new DerAsnSequence(new DerAsnType[] {
                                new DerAsnUtf8String(qualifier.UserNotice.Reference.Organization ?? string.Empty),
                                new DerAsnSequence(qualifier.UserNotice.Reference.NoticeNumbers.Select(c => new DerAsnInteger(new BigInteger(c))).ToArray())
                            }));
                        }
                        if (qualifier.UserNotice?.ExplicitText != null) {
                            noticeSequence.Add(new DerAsnUtf8String(qualifier.UserNotice.ExplicitText));
                        }
                        qualifierValue = new DerAsnSequence(noticeSequence.ToArray());
                    } else {
                        qualifierValue = new DerAsnIa5String(qualifier.CPS_Uri ?? string.Empty);
                    }
                    definitionQualifiers.Add(new DerAsnSequence(new DerAsnType[] { 
                        qualifierId,
                        qualifierValue      
                    }));
                }
                definition.Add(new DerAsnSequence(definitionQualifiers.ToArray()));
                
            }
            list.Add(new DerAsnSequence(definition.ToArray()));
        }
        Value = list.ToArray();
    }

    /// <summary>
    /// constructs the <see cref="CertificatePolicies"/> from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public CertificatePolicies(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the raw data into the list of <see cref="PolicyInformation"/>.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public PolicyInformation[] Extract() {
        var policies = new List<PolicyInformation>();

        foreach (var item in Value) {
            if (!(item is DerAsnSequence)) {
                continue;
            }
            var policySequesce = item as DerAsnSequence;
            var policyIdentifier = ((DerAsnObjectIdentifier)(policySequesce.Value[0])).Value.ToOidString();
            var policy = new PolicyInformation {
                PolicyIdentifier = policyIdentifier,
            };
            if (policySequesce.Value.Length > 1 && policySequesce.Value[1] is DerAsnSequence qualifierListSequence) {
                foreach (DerAsnSequence qualifier in qualifierListSequence.Value) {
                    var qualifierId = ((DerAsnObjectIdentifier)(qualifier.Value[0])).Value.ToOidString();
                    var qualifierValue = new PolicyQualifierInfo {
                        Type = qualifierId == PolicyQualifierInfo.Oid_PolicyQualifier_UNotice ? PolicyQualifierType.UserNotice :
                               qualifierId == PolicyQualifierInfo.Oid_PolicyQualifier_CPS ? PolicyQualifierType.CPS :
                               throw new CryptographicException($"Unknown PolicyQualifierInfo Type {qualifierId}"),

                    };
                    if (qualifierValue.Type == PolicyQualifierType.CPS) {
                        qualifierValue.CPS_Uri = ((DerAsnIa5String)(qualifier.Value[1])).Value;
                    } else {
                        // TODO implement the Read of PolicyInformation in case of PolicyQualifierType UserNotice.
                    }
                    policy.PolicyQualifiers.Add(qualifierValue);
                }
            }
            policies.Add(policy);
        }
        return policies.ToArray();
    }
}

/// <summary>
/// Represents a Policy Information dto
/// </summary>
public class PolicyInformation {
    /// <summary>
    /// EU qualified certificate
    /// </summary>
    const string Oid_QCP = "0.4.0.194112.1";
    /// <summary>
    /// QCP-n
    /// Policy for EU qualified certificate issued to a natural person
    /// </summary>
    public const string Oid_QCP_n = Oid_QCP + ".0";
    /// <summary>
    /// QCP-l
    /// Policy for EU qualified certificate issued to a legal person 
    /// </summary>
    public const string Oid_QCP_l = Oid_QCP + ".1";
    /// <summary>
    /// QCP-n-qscd 
    /// Policy for EU qualified certificate issued to a natural person where the private key and the related
    /// certificate reside on a QSCD
    /// </summary>
    public const string Oid_QCP_n_qscd = Oid_QCP + ".2";
    /// <summary>
    /// QCP-l-qscd 
    /// Policy for EU qualified certificate issued to a legal person where the private key and the related
    /// certificate reside on a QSCD
    /// </summary>
    public const string Oid_QCP_l_qscd = Oid_QCP + ".3";
    /// <summary>
    /// QCP-w
    /// Policy for EU qualified website certificate issued to a natural or a legal person and linking the
    /// website to that person
    /// </summary>
    public const string Oid_QCP_w = Oid_QCP + ".4";
    /// <summary>
    /// For general purpose CAs you can use an universal object identifier with value: 2.5.29.32.0. 
    /// This identifier means “All Issuance Policies” and is sort of wildcard policy. 
    /// Any policy will match this identifier during certificate chain validation
    /// </summary>
    /// <remarks>https://www.sysadmins.lv/blog-en/certificate-policies-extension-all-you-should-know-part-1.aspx</remarks>
    const string Oid_AnyPolicy = CertificatePoliciesExtension.Oid_CertificatePolicies + ".0";

    /// <summary>
    /// The Oid of the policy
    /// </summary>
    public string PolicyIdentifier { get; set; }

    /// <summary>
    /// Policy name
    /// </summary>
    public string Name {
        get {
            switch (PolicyIdentifier) {
                case Oid_QCP_n: return "QCP-n";
                case Oid_QCP_l: return "QCP-l";
                case Oid_QCP_n_qscd: return "QCP-n-qscd";
                case Oid_QCP_l_qscd: return "QCP-l-qscd";
                case Oid_QCP_w: return "QCP-w";
                case Oid_AnyPolicy: return "AnyPolicy";
                case "1.3.76.36.1.1.45.2": return "InfoCert policy for qualified [QWAC] OV certificates";
                case "2.23.140.1.2.2": return "CabForum policy OV Certificates for Web Authentication";
                default: return PolicyIdentifier;
            }
        }
    }

    /// <summary>
    /// Policy Qualifier Information
    /// </summary>
    public List<PolicyQualifierInfo> PolicyQualifiers { get; } = new List<PolicyQualifierInfo>();

    /// <inheritdoc/>
    public override string ToString() => Name ?? base.ToString();

    /// <summary>
    /// Checks whether the policy identifies the certificate as EU qualified certificate.
    /// </summary>
    public bool IsEUQualifiedCertificate => PolicyIdentifier.StartsWith(Oid_QCP);
}

/// <summary>
/// Policy Qualifier
/// </summary>
public class PolicyQualifierInfo {
    /// <summary>
    /// id-pkix 2 Oid 
    /// </summary>
    public const string Oid_PolicyQualifier = "1.3.6.1.5.5.7.2";
    /// <summary>
    /// CPS
    /// </summary>
    public const string Oid_PolicyQualifier_CPS = Oid_PolicyQualifier + ".1";
    /// <summary>
    /// unotice
    /// </summary>
    public const string Oid_PolicyQualifier_UNotice = Oid_PolicyQualifier + ".2";
    internal string Identifier => Oid_PolicyQualifier + "." + (int)Type;

    /// <summary>
    /// The Oid of the qualifier
    /// </summary>
    public PolicyQualifierType Type { get; set; }

    /// <summary>
    /// Qualifier CPS_Uri. Only polulated when <see cref="PolicyQualifierType.CPS"/>
    /// </summary>
    public string CPS_Uri { get; set; }
    /// <summary>
    /// User Notice. Only polulated when <see cref="PolicyQualifierType.UserNotice"/>
    /// </summary>
    public UserNotice UserNotice { get; set; }

    /// <inheritdoc/>
    public override string ToString() => $"{Type} {(Type == PolicyQualifierType.CPS ? CPS_Uri : UserNotice.ToString())}";
}

/// <summary>
/// User notice can be found inside a <see cref="PolicyQualifierInfo"/> of type <see cref="PolicyQualifierType.UserNotice"/>
/// </summary>
public class UserNotice
{
    /// <summary>
    /// Explicit Text (optional)
    /// </summary>
    public string ExplicitText { get; set; }

    /// <summary>
    /// Notice Reference (optional)
    /// </summary>
    public NoticeReference Reference { get; set; }

    /// <summary>
    /// String representation
    /// </summary>
    /// <returns></returns>
    public override string ToString() => $"{ExplicitText ?? Reference?.Organization}";

    /// <summary>
    /// Notice reference
    /// </summary>
    public class NoticeReference
    {
        /// <summary>
        /// Organization
        /// </summary>
        public string Organization { get; set; }
        /// <summary>
        /// Notice numbers.
        /// </summary>
        public int[] NoticeNumbers { get; set; }
    }
}


/// <summary>
/// Identified by id-pkix 2 Oid (1.3.6.1.5.5.7.2)
/// </summary>
public enum PolicyQualifierType
{
    /// <summary>
    /// Statement (CPS) pointer qualifier (1.3.6.1.5.5.7.2.1)
    /// </summary>
    CPS = 1,
    /// <summary>
    /// User notice (unotice) (1.3.6.1.5.5.7.2.2)
    /// </summary>
    UserNotice = 2
}