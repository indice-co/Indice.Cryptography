using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Certificate Revocation List Distribution points extension.
/// <code>
/// cRLDistributionPoints EXTENSION ::= {
///     SYNTAX CRLDistPointSyntax
/// 
///     IDENTIFIED BY id-ce-cRLDistributionPoints
/// }
/// 
/// CRLDistPointSyntax::= SEQUENCE SIZE(1..MAX) OF DistributionPoint
/// 
/// DistributionPoint::= SEQUENCE {
/// 	distributionPoint[0] DistributionPointName OPTIONAL,
/// 	reasons[1] ReasonFlags OPTIONAL,
/// 	cRLIssuer[2] GeneralNames OPTIONAL
/// }
/// 
/// DistributionPointName::= CHOICE {
/// 	fullname[0] GeneralNames,
///     nameRelativeToCRLIssuer[1] RelativeDistinguishedName
/// }
/// 
/// ReasonFlags::= BIT STRING {
///     unused(0),
/// 	keyCompromise(1),
/// 	cACompromise(2)
/// 	affiliationChanged(3),
/// 	superseded(4),
/// 	cessationOfOperation(5),
/// 	certificateHold(6)
/// }
/// </code>
/// </summary>
public class CRLDistributionPointsExtension : X509Extension
{
    //https://tools.ietf.org/html/rfc5280
    /// <summary>
    /// CRL Distribution Points Oid (X509 v2)
    /// </summary>
    public const string Oid_CRLDistributionPoints = "2.5.29.31";

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="distributionPoints"></param>
    /// <param name="critical"></param>
    public CRLDistributionPointsExtension(CRLDistributionPoint[] distributionPoints, bool critical) {
        Oid = new Oid(Oid_CRLDistributionPoints, "CRL Distribution Points");
        Critical = critical;

        var writer = new AsnWriter(AsnEncodingRules.DER);
        var list = new CRLDistributionPoints(distributionPoints);
        list.Encode(writer);
        RawData = writer.Encode();
        
        
        _DistributionPoints = distributionPoints;
        _decoded = true;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public CRLDistributionPointsExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {
    }

    private bool _decoded = false;
    private CRLDistributionPoint[] _DistributionPoints = null!;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public CRLDistributionPoint[] DistributionPoints {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _DistributionPoints;
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
        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            _DistributionPoints = CRLDistributionPoints.Decode(reader);
            _decoded = true;
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode CRL Distribution Points extension.", ex);
        }
    }
}


/// <summary>
/// CRL Distribution Points Der ASN.1 sequense
/// </summary>
public class CRLDistributionPoints : List<CRLDistributionPoint>
{
    /// <summary>
    /// Constructs the <see cref="CRLDistributionPoints"/> from <see cref="CRLDistributionPoint"/>.
    /// </summary>
    /// <param name="distributionPoints"></param>
    public CRLDistributionPoints(IEnumerable<CRLDistributionPoint> distributionPoints) : base(distributionPoints) {
        
    }

    /// <summary>
    /// Encode sequence 
    /// </summary>
    /// <param name="writer"></param>
    public void Encode(AsnWriter writer) {
        writer.PushSequence(); // CRLDistPointSyntax
        {
            foreach (var point in this) {
                writer.PushSequence(); // DistributionPoint
                {
                    if (point.FullName != null && point.FullName.Length > 0) {
                        // distributionPoint [0] DistributionPointName (CHOICE fullName [0])
                        // Write fullName [0] as implicit tag around the GeneralNames sequence
                        var tag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
                        writer.PushSequence(tag);
                        {
                            // fullName [0] GeneralNames - write each URI as [6]
                            foreach (var name in point.FullName) {
                                // GeneralName [6] IA5String (uniformResourceIdentifier)
                                writer.WriteCharacterString(UniversalTagNumber.IA5String, name,
                                    new Asn1Tag(TagClass.ContextSpecific, 6));
                            }
                        }
                        writer.PopSequence(tag);
                    }

                    if (point.Reason.HasValue) {
                        // reasons [1] ReasonFlags
                        byte reasonByte = (byte)point.Reason;
                        var bitArray = new byte[] { reasonByte };
                        writer.WriteBitString(bitArray, 0,
                            new Asn1Tag(TagClass.ContextSpecific, 1));
                    }
                }
                writer.PopSequence(); // End DistributionPoint
            }
        }
        writer.PopSequence(); // End CRLDistPointSyntax
    }

    /// <summary>
    /// Deserializes the raw data into the list of <see cref="Uri"/>.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static CRLDistributionPoint[] Decode(AsnReader reader) {
        var mainSeqReader = reader.ReadSequence();
        var points = new List<CRLDistributionPoint>();
        var contextSpecificTag = new Asn1Tag(TagClass.ContextSpecific, 0);
        while (mainSeqReader.HasData) {
            var pointReader = mainSeqReader.ReadSequence();
            var point = new CRLDistributionPoint();

            // Check for distributionPoint [0]
            var tag = pointReader.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && (int)tag.TagValue == 0) {
                var dpNameReader = pointReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

                // Check for fullname [0]
                var dpTag = dpNameReader.PeekTag();
                if (dpTag.TagClass == TagClass.ContextSpecific && (int)dpTag.TagValue == 0) {
                    var fullNameReader = dpNameReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    var names = new List<string>();

                    while (fullNameReader.HasData) {
                        var gnTag = fullNameReader.PeekTag();
                        if (gnTag.TagClass == TagClass.ContextSpecific && (int)gnTag.TagValue == 6) {
                            var url = fullNameReader.ReadCharacterString(UniversalTagNumber.IA5String,
                                new Asn1Tag(TagClass.ContextSpecific, 6));
                            names.Add(url);
                        } else {
                            // Skip unsupported general name types
                            break;
                        }
                    }

                    point.FullName = names.ToArray();
                }
            }

            // Check for reasons [1]
            if (pointReader.HasData) {
                var reasonTag = pointReader.PeekTag();
                if (reasonTag.TagClass == TagClass.ContextSpecific && (int)reasonTag.TagValue == 1) {
                    var reasonBits = pointReader.ReadBitString(out int _,
                        new Asn1Tag(TagClass.ContextSpecific, 1));
                    if (reasonBits.Length > 0) {
                        point.Reason = (CRLDistributionPoint.ReasonFlags)reasonBits[0];
                    }
                }
            }

            points.Add(point);
        }
        return points.ToArray();
    }
}

/// <summary>
/// Represents a CRL Distribution point dto
/// </summary>
public class CRLDistributionPoint
{
    /// <summary>
    /// The name
    /// </summary>
    public string[] FullName { get; set; } = Array.Empty<string>();

    /// <summary>
    /// The reason flag
    /// </summary>
    public ReasonFlags? Reason { get; set; }

    /// <summary>
    ///  the Name of the CRL issuer
    /// </summary>
    public string? CRLIssuer { get; set; }

    /// <summary>
    /// Distribution Point Flags 
    /// </summary>
    public enum ReasonFlags : byte
    {
        /// <summary>Unused</summary>
        Unused = 0,
        /// <summary>Key compromise</summary>
        KeyCompromise = 1,
        /// <summary>CA compromise</summary>
        CACompromise = 2,
        /// <summary>Affiliation changed</summary>
        AffiliationChanged = 3,
        /// <summary>Superseded</summary>
        Superseded = 4,
        /// <summary>Cessation of operation</summary>
        CessationOfOperation = 5,
        /// <summary>CertificateHold</summary>
        CertificateHold = 6,
        /// <summary>PrivilegeWithdrawn</summary>
        PrivilegeWithdrawn = 7,
        /// <summary>AACompromise</summary>
        AACompromise = 8
    }

    /// <inheritdoc/>
    public override string ToString() => $"CRL DP: {(FullName?.Length > 0 ? string.Join(";", FullName) : "No URLs")}";
}
