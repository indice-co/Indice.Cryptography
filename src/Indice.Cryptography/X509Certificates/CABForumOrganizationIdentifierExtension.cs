using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// CA/Browser Forum OrganizationIdentifier
/// </summary>
/// <remarks>
/// {joint-iso-itu-t(2) international-organizations(23) ca-browser-forum(140) (3) organization-identifier (1)}
/// </remarks>
public class CABForumOrganizationIdentifierExtension : X509Extension
{
    /// <summary>
    /// Extended Evaluation (EV) guidelines Oid (X509 v3)
    /// </summary>
    public const string Oid_CabForumOrganizationIdentifier = "2.23.140.3.1";


    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="organizationIdentifier"></param>
    /// <param name="critical"></param>
    public CABForumOrganizationIdentifierExtension(CABForumOrganizationIdentifier organizationIdentifier, bool critical) {
        Oid = new Oid(Oid_CabForumOrganizationIdentifier, "CRL Distribution Points");
        Critical = critical;
        RawData = EncodeOrganizationIdentifier(organizationIdentifier);
        _OrganizationIdentifier = organizationIdentifier;
        _decoded = true;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public CABForumOrganizationIdentifierExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {
    }

    private bool _decoded = false;
    private CABForumOrganizationIdentifier? _OrganizationIdentifier;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public CABForumOrganizationIdentifier? OrganizationIdentifier {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _OrganizationIdentifier;
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

    private static byte[] EncodeOrganizationIdentifier(CABForumOrganizationIdentifier orgId) {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        {
            writer.WriteCharacterString(UniversalTagNumber.PrintableString, orgId.SchemeIdentifier ?? string.Empty);
            writer.WriteCharacterString(UniversalTagNumber.PrintableString, orgId.Country);
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, orgId.Reference);
        }
        writer.PopSequence();

        return writer.Encode();
    }

    private void DecodeExtension() {

        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            var seqReader = reader.ReadSequence();
            var schemeIdentifier = seqReader.ReadCharacterString(UniversalTagNumber.PrintableString);
            var country = seqReader.ReadCharacterString(UniversalTagNumber.PrintableString);
            var reference = seqReader.ReadCharacterString(UniversalTagNumber.UTF8String);
            _OrganizationIdentifier = new CABForumOrganizationIdentifier(schemeIdentifier, country, reference);
            _decoded = true;
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode CABForumOrganizationIdentifier extension.", ex);
        }
    }
}

/// <summary>
/// CA/Browser Forum OrganizationIdentifier
/// </summary>
public class CABForumOrganizationIdentifier
{
    /// <summary>
    /// Create the cab forum by providing the NCAId (as defined in PSD2)
    /// </summary>
    /// <param name="identifier"></param>
    public CABForumOrganizationIdentifier(NCAId identifier) {
        SchemeIdentifier = identifier.Prefix;
        Country = identifier.CountryCode;
        Reference = string.Join('-', new[] { identifier.SupervisionAuthority, identifier.AuthorizationNumber }.Where(x => !string.IsNullOrEmpty(x)));
    }

    /// <summary>
    /// Create the cab forum by providing its elements
    /// </summary>
    /// <param name="schemeIdentifier">Scheme Identifier. Example "PSD"</param>
    /// <param name="country">Country two letter ISO. Example "GR"</param>
    /// <param name="reference">Reference number.</param>
    public CABForumOrganizationIdentifier(string? schemeIdentifier, string country, string reference) {
        SchemeIdentifier = schemeIdentifier;
        Country = country ?? throw new ArgumentNullException(nameof(country));
        Reference = reference ?? throw new ArgumentNullException(nameof(reference));
    }
    /// <summary>
    /// Scheme Identifier. Example "PSD"
    /// </summary>
    public string? SchemeIdentifier { get; set; }
    /// <summary>
    /// Country two letter ISO. Example "GR"
    /// </summary>
    public string Country { get; set; }
    /// <summary>
    /// Reference number.
    /// </summary>
    public string Reference { get; set; }

    /// <inheritdoc/>
    public override string ToString() => $"{SchemeIdentifier}{Country}-{Reference}";
}
