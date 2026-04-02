using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Certificate Policies Extension.
/// This extension lists certificate policies, recognized by the issuing CA, that apply to the certificate, 
/// together with optional qualifier information pertaining to these certificate policies. 
/// Typically, different certificate policies will relate to different applications which may use the certified key.
/// </summary>
/// <remarks>
/// <code>
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
/// </code>
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
        RawData = EncodeCertificatePolicies(policies);
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
    private PolicyInformation[]? _Policies;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public PolicyInformation[]? Policies {
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

    private static byte[] EncodeCertificatePolicies(PolicyInformation[] policies) {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        {
            foreach (var policy in policies) {
                writer.PushSequence();
                {
                    if (policy.PolicyIdentifier != null) {
                        writer.WriteObjectIdentifier(policy.PolicyIdentifier);
                    }
                    if (policy.PolicyQualifiers?.Count > 0) {
                        writer.PushSequence();
                        {
                            foreach (var qualifier in policy.PolicyQualifiers) {
                                writer.PushSequence();
                                {
                                    writer.WriteObjectIdentifier(qualifier.Identifier);
                                    if (qualifier.Type == PolicyQualifierType.UserNotice) {
                                        writer.PushSequence();
                                        {
                                            if (qualifier.UserNotice?.Reference != null) {
                                                writer.PushSequence();
                                                {
                                                    writer.WriteCharacterString(UniversalTagNumber.UTF8String, qualifier.UserNotice.Reference.Organization ?? string.Empty);
                                                    writer.PushSequence();
                                                    {
                                                        foreach (var noticeNumber in qualifier.UserNotice.Reference.NoticeNumbers) {
                                                            writer.WriteInteger(noticeNumber);
                                                        }
                                                    }
                                                    writer.PopSequence();
                                                }
                                                writer.PopSequence();
                                            }
                                            if (qualifier.UserNotice?.ExplicitText != null) {
                                                writer.WriteCharacterString(UniversalTagNumber.UTF8String, qualifier.UserNotice.ExplicitText);
                                            }
                                        }
                                        writer.PopSequence();
                                    } else {
                                        writer.WriteCharacterString(UniversalTagNumber.IA5String, qualifier.CPS_Uri ?? string.Empty);
                                    }
                                }
                                writer.PopSequence();
                            }
                        }
                        writer.PopSequence();
                    }
                }
                writer.PopSequence();
            }
        }
        writer.PopSequence();

        return writer.Encode();
    }

    private void DecodeExtension() {
        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            var mainSeq = reader.ReadSequence();
            var policies = new List<PolicyInformation>();

            while (mainSeq.HasData) {
                var policySeq = mainSeq.ReadSequence();
                var policyIdentifier = policySeq.ReadObjectIdentifier();
                var policy = new PolicyInformation {
                    PolicyIdentifier = policyIdentifier,
                };

                if (policySeq.HasData && policySeq.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) {
                    var qualifierSeq = policySeq.ReadSequence();
                    while (qualifierSeq.HasData) {
                        var qualifierItemSeq = qualifierSeq.ReadSequence();
                        var qualifierId = qualifierItemSeq.ReadObjectIdentifier();
                        var qualifierValue = new PolicyQualifierInfo {
                            Type = qualifierId == PolicyQualifierInfo.Oid_PolicyQualifier_UNotice ? PolicyQualifierType.UserNotice :
                                   qualifierId == PolicyQualifierInfo.Oid_PolicyQualifier_CPS ? PolicyQualifierType.CPS :
                                   throw new InvalidOperationException($"Unknown PolicyQualifierInfo Type {qualifierId}")
                        };

                        if (qualifierValue.Type == PolicyQualifierType.CPS) {
                            qualifierValue.CPS_Uri = qualifierItemSeq.ReadCharacterString(UniversalTagNumber.IA5String);
                        } else if (qualifierValue.Type == PolicyQualifierType.UserNotice) {
                            var userNoticeSeq = qualifierItemSeq.ReadSequence();
                            var userNotice = new UserNotice();

                            if (userNoticeSeq.HasData && userNoticeSeq.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) {
                                var noticeRefSeq = userNoticeSeq.ReadSequence();
                                var org = noticeRefSeq.ReadCharacterString(UniversalTagNumber.UTF8String);
                                var noticeNumbersSeq = noticeRefSeq.ReadSequence();
                                var noticeNumbers = new List<int>();
                                while (noticeNumbersSeq.HasData) {
                                    noticeNumbers.Add((int)noticeNumbersSeq.ReadInteger());
                                }
                                userNotice.Reference = new UserNotice.NoticeReference {
                                    Organization = org,
                                    NoticeNumbers = noticeNumbers.ToArray()
                                };
                            }

                            if (userNoticeSeq.HasData) {
                                userNotice.ExplicitText = userNoticeSeq.ReadCharacterString(UniversalTagNumber.UTF8String);
                            }

                            qualifierValue.UserNotice = userNotice;
                        }

                        policy.PolicyQualifiers.Add(qualifierValue);
                    }
                }

                policies.Add(policy);
            }

            _Policies = policies.ToArray();
            _decoded = true;
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode Certificate Policies extension.", ex);
        }
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
    /// This identifier means "All Issuance Policies" and is sort of wildcard policy. 
    /// Any policy will match this identifier during certificate chain validation
    /// </summary>
    /// <remarks>https://www.sysadmins.lv/blog-en/certificate-policies-extension-all-you-should-know-part-1.aspx</remarks>
    const string Oid_AnyPolicy = CertificatePoliciesExtension.Oid_CertificatePolicies + ".0";

    /// <summary>
    /// The Oid of the policy
    /// </summary>
    public string? PolicyIdentifier { get; set; }

    /// <summary>Policy name</summary>
    public string? Name => 
        PolicyIdentifier switch {
                Oid_QCP_n => "QCP-n",
                Oid_QCP_l => "QCP-l",
                Oid_QCP_n_qscd => "QCP-n-qscd",
                Oid_QCP_l_qscd => "QCP-l-qscd",
                Oid_QCP_w => "QCP-w",
                Oid_AnyPolicy => "AnyPolicy",
                "1.3.76.36.1.1.45.2" => "InfoCert policy for qualified [QWAC] OV certificates",
                "2.23.140.1.2.2" => "CabForum policy OV Certificates for Web Authentication",
                _ => PolicyIdentifier,
            };
     

    /// <summary>
    /// Policy Qualifier Information
    /// </summary>
    public List<PolicyQualifierInfo> PolicyQualifiers { get; } = new List<PolicyQualifierInfo>();

    /// <inheritdoc/>
    public override string? ToString() => Name ?? base.ToString();

    /// <summary>
    /// Checks whether the policy identifies the certificate as EU qualified certificate.
    /// </summary>
    public bool IsEUQualifiedCertificate => PolicyIdentifier!.StartsWith(Oid_QCP);
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

    /// <summary>
    /// The Oid of the qualifier
    /// </summary>
    public PolicyQualifierType Type { get; set; }

    /// <summary>
    /// The Identifier OID string
    /// </summary>
    public string Identifier => Oid_PolicyQualifier + "." + (int)Type;

    /// <summary>
    /// Qualifier CPS_Uri. Only polulated when <see cref="PolicyQualifierType.CPS"/>
    /// </summary>
    public string CPS_Uri { get; set; } = null!;
    /// <summary>
    /// User Notice. Only polulated when <see cref="PolicyQualifierType.UserNotice"/>
    /// </summary>
    public UserNotice UserNotice { get; set; } = null!;

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
    public string? ExplicitText { get; set; }

    /// <summary>
    /// Notice Reference (optional)
    /// </summary>
    public NoticeReference? Reference { get; set; }

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
        public string Organization { get; set; } = null!;
        /// <summary>
        /// Notice numbers.
        /// </summary>
        public int[] NoticeNumbers { get; set; } = null!;
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
