using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DerConverter;
using DerConverter.Asn.KnownTypes;
using DerConverter.Asn;

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
    /// Extended Validation (EV) guidelines Oid (X509 v3)
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
        var container = new DerAsnSequence(new DerAsnType[] {
            new DerAsnPrintableString(organizationIdentifier.SchemeIdentifier),
            new DerAsnPrintableString(organizationIdentifier.Country),
            new DerAsnUtf8String(organizationIdentifier.Reference),
        });
        RawData = DerConvert.Encode(container).ToArray();
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

    private void DecodeExtension() {
        _OrganizationIdentifier = new CABForumOrganizationIdentifier();
        var root = DerConvert.Decode(RawData) as DerAsnSequence;
        _OrganizationIdentifier.SchemeIdentifier = ((DerAsnPrintableString)root!.Value[0]).Value;
        _OrganizationIdentifier.Country = ((DerAsnPrintableString)root.Value[1]).Value;
        _OrganizationIdentifier.Reference = ((DerAsnUtf8String)root.Value[2]).Value;
        _decoded = true;
    }
}

/// <summary>
/// CA/Browser Forum OrganizationIdentifier
/// </summary>
public class CABForumOrganizationIdentifier
{
    /// <summary>
    /// default constructor
    /// </summary>
    public CABForumOrganizationIdentifier() {

    }
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
    /// Scheme Identifier. Example "PSD"
    /// </summary>
    public string? SchemeIdentifier { get; set; }
    /// <summary>
    /// Country two letter ISO. Example "GR"
    /// </summary>
    public string? Country { get; set; }
    /// <summary>
    /// Reference number.
    /// </summary>
    public string? Reference { get; set; }

    /// <inheritdoc/>
    public override string ToString() => $"{SchemeIdentifier}{Country}-{Reference}";
}
