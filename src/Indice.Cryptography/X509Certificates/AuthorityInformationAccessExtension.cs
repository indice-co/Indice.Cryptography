using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DerConverter;
using DerConverter.Asn;
using DerConverter.Asn.KnownTypes;
using Indice.Cryptography.X509Certificates.DerAsnTypes;

namespace Indice.Cryptography.X509Certificates;

//https://tools.ietf.org/html/rfc4325#ref-X.680
/// <summary>
/// Authority Information Access Extension
/// 
/// id-pe-authorityInfoAccess OBJECT IDENTIFIER  ::=  { id-pe 1 }
///   
/// AuthorityInfoAccessSyntax  ::=  SEQUENCE SIZE(1..MAX) OF
///                         AccessDescription
/// 
/// AccessDescription::=  SEQUENCE {
///    accessMethod OBJECT IDENTIFIER,
///    accessLocation GeneralName  }
/// 
/// id-ad OBJECT IDENTIFIER::=  { id-pkix 48 }
/// 
/// id-ad-caIssuers OBJECT IDENTIFIER::=  { id-ad 2 }
/// </summary>
public class AuthorityInformationAccessExtension : X509Extension
{
    /// <summary>
    /// Authority Information Access Oid (X509 v3)
    /// </summary>
    public const string Oid_AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="accessDescritpions"></param>
    /// <param name="critical"></param>
    public AuthorityInformationAccessExtension(AccessDescription[] accessDescritpions, bool critical) {
        Oid = new Oid(Oid_AuthorityInformationAccess, "Authority Information Access");
        Critical = critical;
        RawData = DerConvert.Encode(new AccessDescriptionList(accessDescritpions)).ToArray();
        _AccessDescriptions = accessDescritpions;
        _decoded = true;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public AuthorityInformationAccessExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {

    }

    private bool _decoded = false;
    private AccessDescription[] _AccessDescriptions;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public AccessDescription[] AccessDescriptions {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _AccessDescriptions;
        }
    }

    /// <summary>
    /// Copies the extension properties of the specified <see cref="AsnEncodedData"/> object.
    /// </summary>
    /// <param name="asnEncodedData">The <see cref="AsnEncodedData"/>  to be copied.</param>
    public override void CopyFrom(AsnEncodedData asnEncodedData) {
        base.CopyFrom(asnEncodedData);
        _decoded = false;
    }

    private void DecodeExtension() {
        using (var decoder = new DefaultDerAsnDecoder()) {
            decoder.RegisterType(ContextSpecificString.Id, (dcdr, identifier, data) => new ContextSpecificString(dcdr, identifier, data));
            var sequence = decoder.Decode(RawData) as DerAsnSequence;
            _AccessDescriptions = new AccessDescriptionList(sequence.Value).Extract();
            _decoded = true;
        }
        
    }

}

/// <summary>
/// AccessDescription specifying id-ad-caIssuers as the accessMethod.
/// Access method types other than id-ad-ca Issuers MUST NOT be included.
/// At least one instance of AccessDescription SHOULD specify an
/// accessLocation that is an HTTP[HTTP / 1.1] or Lightweight Directory
/// Access Protocol[LDAP] Uniform Resource Identifier[URI].
/// </summary>
public class AccessDescriptionList : DerAsnSequence
{
    /// <summary>
    /// Authority Information Access Oid (X509 v3)
    /// </summary>
    public const string Oid_AccessDescription = "1.3.6.1.5.5.7.48";
    /// <summary>
    /// Access description of type id-ad-ocsp Oid
    /// </summary>
    public const string Oid_OCSP = Oid_AccessDescription + ".1";
    /// <summary>
    /// Access description of type id-ad-caIssuers Oid
    /// </summary>
    public const string Oid_CertificationAuthorityIssuer = Oid_AccessDescription + ".2";
    /// <summary>
    /// is used when revocation information for the
    /// certificate containing this extension is available using the Online
    /// Certificate Status Protocol(OCSP) [RFC 2560].
    /// </summary>
    public const string Oid_OCP = "1.3.6.1.5.5.7.48.1";

    private static int[] Oid2Array(string oid) {
        return oid.Split('.').Select(x => int.Parse(x)).ToArray();
    }

    /// <summary>
    /// Constructs the <see cref="AccessDescriptionList"/> from <see cref="Uri"/>.
    /// </summary>
    /// <param name="descriptions"></param>
    public AccessDescriptionList(AccessDescription[] descriptions) : base(new DerAsnType[0]) {
        var list = new List<DerAsnSequence>();
        foreach (var description in descriptions) {
            var id = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid2Array(Oid_AccessDescription + "." + (int)description.AccessMethod));
            var alternativeName = new ContextSpecificString(description.AccessLocation);
            var accessDescription = new DerAsnSequence(new DerAsnType[] { id, alternativeName });
            list.Add(accessDescription);
        }
        Value = list.ToArray();
    }

    /// <summary>
    /// constructs the <see cref="AccessDescriptionList"/> from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public AccessDescriptionList(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the raw data into the list of <see cref="AccessDescription"/>.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public AccessDescription[] Extract() {
        var descriptions = new List<AccessDescription>();
        
        foreach (var item in Value) {
            if (!(item is DerAsnSequence)) {
                continue;
            }
            var accessDescription = item as DerAsnSequence;
            var accessMethod = accessDescription.Value[0] as DerAsnObjectIdentifier;
            var accessLocation = accessDescription.Value[1] as ContextSpecificString;

            descriptions.Add(new AccessDescription {
                AccessMethod = (AccessDescription.AccessMethodType)(int)accessMethod.Value[accessMethod.Value.Length - 1],
                AccessLocation = accessLocation.Value
            });
        }
        return descriptions.ToArray();
    }
}

/// <summary>
/// Access Description dto for Authority Information Access extension
/// </summary>
public class AccessDescription
{
    /// <summary>
    /// OCSP or *.cer endpoints
    /// </summary>
    public AccessMethodType AccessMethod { get; set; }

    /// <summary>
    /// Url. This is an array in case there are both ldap and http protocol based urls.
    /// </summary>
    public string AccessLocation { get; set; }

    /// <summary>
    /// Access Method enum.
    /// </summary>
    public enum AccessMethodType
    {
        /// <summary>
        /// Online Certificate Status Protocol (OCSP). Reperesents urls that point to OCSP protocol endpoint.
        /// </summary>
        OnlineCertificateStatusProtocol = 1,

        /// <summary>
        /// Certificate authority issuers. represents urls that point to *.cer endpoint with the issuers public key certificate.
        /// </summary>
        CertificationAuthorityIssuer = 2,
    }

    /// <inheritdoc/>
    public override string ToString() => !string.IsNullOrEmpty(AccessLocation) ?
                                            $"{AccessLocation} ({(AccessMethod == AccessMethodType.CertificationAuthorityIssuer ? "cer" : "OSCP")})" :
                                        base.ToString();
}
