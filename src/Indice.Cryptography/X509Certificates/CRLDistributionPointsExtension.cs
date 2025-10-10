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

/// <summary>
/// Certificate Revocation List Distribution points extension.
/// 
/// cRLDistributionPoints EXTENSION ::= {
/// SYNTAX CRLDistPointSyntax
/// 
/// IDENTIFIED BY id-ce-cRLDistributionPoints
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
        RawData = DerConvert.Encode(new CRLDistributionPoints(distributionPoints)).ToArray();
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
    private CRLDistributionPoint[] _DistributionPoints;

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
        using (var decoder = new DefaultDerAsnDecoder()) {
            decoder.RegisterType(ContextSpecificSequence.Id, (dcdr, identifier, data) => new ContextSpecificSequence(dcdr, identifier, data));
            decoder.RegisterType(ContextSpecificString.Id, (dcdr, identifier, data) => new ContextSpecificString(dcdr, identifier, data));
            var sequence = decoder.Decode(RawData) as DerAsnSequence;
            _DistributionPoints = new CRLDistributionPoints(sequence.Value).Extract();
            _decoded = true;
        }
    }

}

/// <summary>
/// CRL Distribution Points Der ASN.1 sequense
/// </summary>
public class CRLDistributionPoints : DerAsnSequence
{
    /// <summary>
    /// Constructs the <see cref="CRLDistributionPoints"/> from <see cref="CRLDistributionPoint"/>.
    /// </summary>
    /// <param name="distributionPoints"></param>
    public CRLDistributionPoints(CRLDistributionPoint[] distributionPoints) : base(new DerAsnType[0]) {
        var list = new List<DerAsnSequence>();
        foreach (var point in distributionPoints) {
            var definition = new List<DerAsnType>();
            if (point.FullName != null) {
                var names = point.FullName.Select(x => new ContextSpecificString(x)).ToArray();
                var fullName = new ContextSpecificSequence(names);
                var distributionPointName = new ContextSpecificSequence(new[] { fullName });
                definition.Add(distributionPointName);
            }
            if (point.Reason != null) {
                var reason = new DerAsnBitString(new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Primitive, DerAsnKnownTypeTags.Primitive.ObjectIdentifier), new System.Collections.BitArray(new[] { (byte)point.Reason }));
                definition.Add(reason);
            }
            list.Add(new DerAsnSequence(definition.ToArray()));
        }
        Value = list.ToArray();
    }

    /// <summary>
    /// constructs the <see cref="CRLDistributionPoints"/> from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public CRLDistributionPoints(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the raw data into the list of <see cref="Uri"/>.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public CRLDistributionPoint[] Extract() {
        var points = new List<CRLDistributionPoint>();
        
        foreach (var item in Value) {
            if (!(item is DerAsnSequence)) {
                continue;
            }
            var crlDistributionPoint = item as DerAsnSequence;
            var distributionPointName = crlDistributionPoint.Value[0] as ContextSpecificSequence;
            var fullName = distributionPointName.Value[0] as ContextSpecificSequence;

            var names = fullName.Value.Cast<ContextSpecificString>().Select(x => x.Value).ToArray();

            points.Add(new CRLDistributionPoint {
                FullName = names
            });
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
    public string[] FullName { get; set; }
    /// <summary>
    /// The reason flag
    /// </summary>
    public ReasonFlags? Reason { get; set; }

    /// <summary>
    ///  the Name of the CRL issuer
    /// </summary>
    public string CRLIssuer { get; set; }

    /// <summary>
    /// Distribution Point Flags 
    /// </summary>
    public enum ReasonFlags : byte
    {
        /// <summary>
        /// Unused
        /// </summary>
        Unused = 0,
        /// <summary>
        /// Key Compromise
        /// </summary>
        KeyCompromise = 1,
        /// <summary>
        /// CACompromise
        /// </summary>
        CACompromise = 2,
        /// <summary>
        /// AffiliationChanged
        /// </summary>
        AffiliationChanged = 3,
        /// <summary>
        /// Superseded
        /// </summary>
        Superseded = 4,
        /// <summary>
        /// CessationOfOperation
        /// </summary>
        CessationOfOperation = 5,
        /// <summary>
        /// CertificateHold
        /// </summary>
        CertificateHold = 6,
        /// <summary>
        /// PrivilegeWithdrawn
        /// </summary>
        PrivilegeWithdrawn = 7,
        /// <summary>
        /// AACompromise
        /// </summary>
        AACompromise = 8
    }
}
