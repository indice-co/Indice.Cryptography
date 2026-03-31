using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

        var writer = new AsnWriter(AsnEncodingRules.DER);
        var list = new AccessDescriptionList(accessDescritpions);
        list.Encode(writer);
        RawData = writer.Encode();

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
    private AccessDescription[] _AccessDescriptions = null!;

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
        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            _AccessDescriptions = AccessDescriptionList.Decode(reader);
            _decoded = true;
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode AuthorityInformationAccess extension.", ex);
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
public class AccessDescriptionList : List<AccessDescription>
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

    /// <summary>
    /// Constructs the <see cref="AccessDescriptionList"/>.
    /// </summary>
    public AccessDescriptionList(IEnumerable<AccessDescription> accessDescriptions) : base(accessDescriptions) {
            
    }

    /// <summary>Encodes the extension part on the writer</summary>
    /// <param name="writer">The writer to write to</param>
    public void Encode(AsnWriter writer) {
        writer.PushSequence(); // SEQUENCE OF AccessDescription
        {
            foreach (var description in this) {
                writer.PushSequence(); // AccessDescription
                {
                    // accessMethod OID
                    string oid = AccessDescriptionList.Oid_AccessDescription + "." + (int)description.AccessMethod;
                    writer.WriteObjectIdentifier(oid);

                    // accessLocation GeneralName [6] IA5String (context-specific)
                    writer.WriteCharacterString(UniversalTagNumber.IA5String,
                        description.AccessLocation ?? string.Empty,
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                }
                writer.PopSequence(); // End AccessDescription
            }
        }
        writer.PopSequence(); // End SEQUENCE OF    
    }

    /// <summary>Decodes the extension part from the reader</summary>
    /// <param name="reader">The reader</param>
    /// <returns>The sequence of <see cref="AccessDescription"/></returns>
    public static AccessDescription[] Decode(AsnReader reader) {
        var sequenceReader = reader.ReadSequence();
        var descriptions = new List<AccessDescription>();

        while (sequenceReader.HasData) {
            var accessDescriptionReader = sequenceReader.ReadSequence();
            var oid = accessDescriptionReader.ReadObjectIdentifier();

            // Parse the OID to get the access method (last component)
            var oidParts = oid.Split('.');
            if (!int.TryParse(oidParts[^1], out int accessMethodValue)) {
                continue;
            }

            // Read the accessLocation with context-specific [6] tag
            string? accessLocation = null;
            if (accessDescriptionReader.HasData) {
                var tag = accessDescriptionReader.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific && (int)tag.TagValue == 6) {
                    accessLocation = accessDescriptionReader.ReadCharacterString(UniversalTagNumber.IA5String,
                        new Asn1Tag(TagClass.ContextSpecific, 6));
                }
            }

            descriptions.Add(new AccessDescription {
                AccessMethod = (AccessDescription.AccessMethodType)accessMethodValue,
                AccessLocation = accessLocation
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
    public string? AccessLocation { get; set; }

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
    public override string? ToString() => !string.IsNullOrEmpty(AccessLocation) ?
                                            $"{AccessLocation} ({(AccessMethod == AccessMethodType.CertificationAuthorityIssuer ? "cer" : "OSCP")})" :
                                        base.ToString();
}
