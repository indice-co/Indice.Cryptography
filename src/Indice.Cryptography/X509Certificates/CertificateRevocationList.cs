using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Certificate revocation list CRL encoder/decoder using System.Formats.Asn1
/// </summary>
public class CertificateRevocationListSequence
{
    /// <summary>
    /// Oid for CRL reason
    /// </summary>
    public const string Oid_CRL_Reason = "2.5.29.21";
    /// <summary>
    /// Oid for the signing algorithm.
    /// </summary>
    public const string Oid_sha256RSA = "1.2.840.113549.1.1.11";
    /// <summary>
    /// Oid for issuer Subject CN.
    /// </summary>
    public const string Oid_Issuer_CN = "2.5.4.3";
    /// <summary>
    /// Oid for issuer Subject C.
    /// </summary>
    public const string Oid_Issuer_C = "2.5.4.6";
    /// <summary>
    /// Oid for issuer Subject O.
    /// </summary>
    public const string Oid_Issuer_O = "2.5.4.10";
    /// <summary>
    /// Oid for Authority Key Identifier.
    /// </summary>
    public const string Oid_AuthorityKey = "2.5.29.35";
    /// <summary>
    /// Oid for CRL Number.
    /// </summary>
    public const string Oid_CRLNumber = "2.5.29.20";

    private CertificateRevocationList? _crl;
    private byte[]? _rawTbsCertList;

    /// <summary>
    /// Constructs the <see cref="CertificateRevocationListSequence"/> from <see cref="CertificateRevocationList"/>.
    /// </summary>
    /// <param name="crl">The CRL data to encode</param>
    public CertificateRevocationListSequence(CertificateRevocationList crl) {
        _crl = crl ?? throw new ArgumentNullException(nameof(crl));
        _rawTbsCertList = EncodeTbsCertList(crl);
    }

    /// <summary>
    /// Constructs from raw DER bytes (for deserialization)
    /// </summary>
    internal CertificateRevocationListSequence(byte[] rawTbsCertList) {
        _rawTbsCertList = rawTbsCertList;
    }

    /// <summary>
    /// Gets the underlying CRL data (decoded on first access)
    /// </summary>
    public CertificateRevocationList Crl {
        get {
            if (_crl == null && _rawTbsCertList != null) {
                _crl = DecodeTbsCertList(_rawTbsCertList);
            }
            return _crl ?? throw new InvalidOperationException("CRL data not available");
        }
    }

    /// <summary>
    /// Encodes the TBSCertList to DER format
    /// </summary>
    private static byte[] EncodeTbsCertList(CertificateRevocationList crl) {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        {
            // Version (v2 = 1)
            writer.WriteInteger(1);

            // Signature Algorithm
            writer.PushSequence();
            {
                writer.WriteObjectIdentifier(Oid_sha256RSA);
                writer.WriteNull();
            }
            writer.PopSequence();

            // Issuer Name (RDNSequence)
            writer.PushSequence();
            {
                // C (Country)
                writer.PushSequence();
                {
                    writer.PushSequence();
                    {
                        writer.WriteObjectIdentifier(Oid_Issuer_C);
                        writer.WriteCharacterString(UniversalTagNumber.PrintableString, crl.Country ?? string.Empty);
                    }
                    writer.PopSequence();
                }
                writer.PopSequence();

                // O (Organization)
                writer.PushSequence();
                {
                    writer.PushSequence();
                    {
                        writer.WriteObjectIdentifier(Oid_Issuer_O);
                        writer.WriteCharacterString(UniversalTagNumber.PrintableString, crl.Organization ?? string.Empty);
                    }
                    writer.PopSequence();
                }
                writer.PopSequence();

                // CN (Common Name)
                writer.PushSequence();
                {
                    writer.PushSequence();
                    {
                        writer.WriteObjectIdentifier(Oid_Issuer_CN);
                        writer.WriteCharacterString(UniversalTagNumber.PrintableString, crl.IssuerCommonName ?? string.Empty);
                    }
                    writer.PopSequence();
                }
                writer.PopSequence();
            }
            writer.PopSequence();

            // This Update (Effective Date)
            writer.WriteGeneralizedTime(crl.EffectiveDate);

            // Next Update
            writer.WriteGeneralizedTime(crl.NextUpdate);

            // Revoked Certificates (optional but we include if present)
            if (crl.Items.Count > 0) {
                writer.PushSequence();
                {
                    foreach (var cert in crl.Items) {
                        writer.PushSequence();
                        {
                            // Serial Number
                            var serialNumber = BigInteger.Parse(cert.SerialNumber!.ToUpper(), System.Globalization.NumberStyles.AllowHexSpecifier);
                            writer.WriteInteger(serialNumber);

                            // Revocation Date
                            writer.WriteGeneralizedTime(cert.RevocationDate);

                            // CRL Entry Extensions
                            writer.PushSequence();
                            {
                                // CRL Reason Code
                                writer.PushSequence();
                                {
                                    writer.WriteObjectIdentifier(Oid_CRL_Reason);
                                    // Write the reason code as an ENUMERATED in an OCTET STRING
                                    var reasonWriter = new AsnWriter(AsnEncodingRules.DER);
                                    reasonWriter.WriteEnumeratedValue(cert.ReasonCode);
                                    writer.WriteOctetString(reasonWriter.Encode());
                                }
                                writer.PopSequence();
                            }
                            writer.PopSequence();
                        }
                        writer.PopSequence();
                    }
                }
                writer.PopSequence();
            }

            // CRL Extensions (optional, context-specific [0])
            writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, isConstructed: true, tagValue: 0));
            {
                // Authority Key Identifier Extension
                writer.PushSequence();
                {
                    writer.WriteObjectIdentifier(Oid_AuthorityKey);
                    // Write the authority key identifier
                    var authKeyWriter = new AsnWriter(AsnEncodingRules.DER);
                    authKeyWriter.PushSequence();
                    {
                        var keyBytes = crl.AuthorizationKeyId?.HexToBytes() ?? Array.Empty<byte>();
                        authKeyWriter.WriteOctetString(keyBytes, new Asn1Tag(TagClass.ContextSpecific, isConstructed: false, tagValue: 0));
                    }
                    authKeyWriter.PopSequence();
                    writer.WriteOctetString(authKeyWriter.Encode());
                }
                writer.PopSequence();

                // CRL Number Extension
                writer.PushSequence();
                {
                    writer.WriteObjectIdentifier(Oid_CRLNumber);
                    // Write the CRL number
                    var crlNumWriter = new AsnWriter(AsnEncodingRules.DER);
                    crlNumWriter.WriteInteger(crl.CrlNumber);
                    writer.WriteOctetString(crlNumWriter.Encode());
                }
                writer.PopSequence();
            }
            writer.PopSequence(new Asn1Tag(TagClass.ContextSpecific, isConstructed: true, tagValue: 0));
        }
        writer.PopSequence();

        return writer.Encode();
    }

    /// <summary>
    /// Decodes a TBSCertList from DER format
    /// </summary>
    private static CertificateRevocationList DecodeTbsCertList(byte[] data) {
        var crl = new CertificateRevocationList();
        
        var reader = new AsnReader(data, AsnEncodingRules.DER);
        
        // Check if this is a signed CRL (SEQUENCE containing TBSCertList, AlgorithmIdentifier, Signature)
        // or just a TBSCertList directly
        var firstTag = reader.PeekTag();
        AsnReader tbsCertList;
        
        if (firstTag.HasSameClassAndValue(Asn1Tag.Sequence)) {
            // Could be either signed CRL or TBSCertList
            // Try to determine by looking ahead
            var tempReader = reader.ReadSequence();
            
            // Check if first element is an INTEGER (version) - that would indicate it's TBSCertList
            if (tempReader.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) {
                // It's a TBSCertList
                tbsCertList = tempReader;
            } else {
                // It might be a signed CRL, so this sequence contains TBSCertList, Algorithm, Signature
                // The first element should still be the TBSCertList (which is also a SEQUENCE)
                if (tempReader.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) {
                    // Read the TBSCertList
                    tbsCertList = tempReader.ReadSequence();
                } else {
                    throw new InvalidOperationException("Invalid CRL structure");
                }
            }
        } else {
            throw new InvalidOperationException("CRL data must start with a SEQUENCE");
        }

        // Version (optional, v1 if not present, v2 = 1)
        if (tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) {
            _ = tbsCertList.ReadInteger();
        }

        // Signature Algorithm
        _ = tbsCertList.ReadSequence();

        // Issuer Name (RDNSequence)
        // Try to parse flexibly - real-world CRLs may have variations
        try {
            var issuerSeq = tbsCertList.ReadSequence();
            while (issuerSeq.HasData) {
                try {
                    // RDN is a SET OF AttributeTypeAndValue
                    var rdnTag = issuerSeq.PeekTag();
                    
                    // Try to handle as SET (which is what real CRLs use)
                    if (rdnTag.HasSameClassAndValue(new Asn1Tag(TagClass.Universal, isConstructed: true, tagValue: 17))) {
                        // SET tag - read the raw bytes
                        var setBytes = issuerSeq.ReadEncodedValue();
                        var setReader = new AsnReader(setBytes, AsnEncodingRules.DER);
                        
                        // Peek inside the SET to see what's there
                        if (setReader.HasData) {
                            var innerTag = setReader.PeekTag();
                            if (innerTag.HasSameClassAndValue(Asn1Tag.Sequence)) {
                                // It's a proper SEQUENCE inside the SET
                                var attrSeq = setReader.ReadSequence();
                                var oid = attrSeq.ReadObjectIdentifier();
                                // Try PrintableString first, then fall back to other string types
                                string value = "";
                                if (attrSeq.HasData) {
                                    var tag = attrSeq.PeekTag();
                                    if (tag.TagValue == (int)UniversalTagNumber.PrintableString) {
                                        value = attrSeq.ReadCharacterString(UniversalTagNumber.PrintableString);
                                    } else if (tag.TagValue == (int)UniversalTagNumber.UTF8String) {
                                        value = attrSeq.ReadCharacterString(UniversalTagNumber.UTF8String);
                                    } else if (tag.TagValue == (int)UniversalTagNumber.IA5String) {
                                        value = attrSeq.ReadCharacterString(UniversalTagNumber.IA5String);
                                    } else {
                                        try {
                                            value = attrSeq.ReadCharacterString(UniversalTagNumber.PrintableString);
                                        } catch {
                                            value = attrSeq.ReadCharacterString(UniversalTagNumber.UTF8String);
                                        }
                                    }
                                }

                                switch (oid) {
                                    case Oid_Issuer_C:
                                        crl.Country = value;
                                        break;
                                    case Oid_Issuer_O:
                                        crl.Organization = value;
                                        break;
                                    case Oid_Issuer_CN:
                                        crl.IssuerCommonName = value;
                                        break;
                                }
                            } else {
                                // Unexpected format, skip this RDN
                                continue;
                            }
                        }
                    } else if (rdnTag.HasSameClassAndValue(Asn1Tag.Sequence)) {
                        // Handle legacy SEQUENCE format (less common)
                        var rdn = issuerSeq.ReadSequence();
                        var attrSeq = rdn.ReadSequence();
                        var oid = attrSeq.ReadObjectIdentifier();
                        var value = attrSeq.ReadCharacterString(UniversalTagNumber.PrintableString);

                        switch (oid) {
                            case Oid_Issuer_C:
                                crl.Country = value;
                                break;
                            case Oid_Issuer_O:
                                crl.Organization = value;
                                break;
                            case Oid_Issuer_CN:
                                crl.IssuerCommonName = value;
                                break;
                        }
                    }
                } catch {
                    // If we can't parse this RDN, skip it and continue
                    continue;
                }
            }
        } catch {
            // If we can't parse the issuer name at all, continue - it's not critical
        }

        // This Update - handle both UTCTime and GeneralizedTime
        crl.EffectiveDate = ReadTime(tbsCertList).DateTime;

        // Next Update - handle both UTCTime and GeneralizedTime
        crl.NextUpdate = ReadTime(tbsCertList).DateTime;

        // Revoked Certificates (optional)
        if (tbsCertList.HasData && tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) {
            var revokedCertsSeq = tbsCertList.ReadSequence();
            while (revokedCertsSeq.HasData) {
                var certSeq = revokedCertsSeq.ReadSequence();
                var serialNumber = certSeq.ReadInteger();
                var revocationDate = ReadTime(certSeq).DateTime;
                var reasonCode = RevokedCertificate.CRLReasonCode.Unused;

                if (certSeq.HasData && certSeq.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) {
                    var extensionsSeq = certSeq.ReadSequence();
                    while (extensionsSeq.HasData) {
                        var extSeq = extensionsSeq.ReadSequence();
                        var extOid = extSeq.ReadObjectIdentifier();
                        if (extOid == Oid_CRL_Reason) {
                            var reasonBytes = extSeq.ReadOctetString();
                            var reasonReader = new AsnReader(reasonBytes, AsnEncodingRules.DER);
                            reasonCode = (RevokedCertificate.CRLReasonCode)reasonReader.ReadEnumeratedValue(typeof(RevokedCertificate.CRLReasonCode));
                        }
                    }
                }

                crl.Items.Add(new RevokedCertificate {
                    SerialNumber = serialNumber.ToString("x16"),
                    RevocationDate = revocationDate,
                    ReasonCode = reasonCode
                });
            }
        }

        // CRL Extensions (optional, context-specific [0])
        try {
            if (tbsCertList.HasData && tbsCertList.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, isConstructed: true, tagValue: 0))) {
                var extSeq = tbsCertList.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, isConstructed: true, tagValue: 0));
                while (extSeq.HasData) {
                    try {
                        var extension = extSeq.ReadSequence();
                        var extOid = extension.ReadObjectIdentifier();
                        var extValue = extension.ReadOctetString();

                        switch (extOid) {
                            case Oid_AuthorityKey:
                                try {
                                    var authKeyReader = new AsnReader(extValue, AsnEncodingRules.DER);
                                    var authKeySeq = authKeyReader.ReadSequence();
                                    if (authKeySeq.HasData) {
                                        var keyBytes = authKeySeq.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, isConstructed: false, tagValue: 0));
                                        crl.AuthorizationKeyId = string.Concat(keyBytes.Select(b => b.ToString("X2")));
                                    }
                                } catch {
                                    // Ignore errors in parsing authority key
                                }
                                break;
                            case Oid_CRLNumber:
                                try {
                                    var crlNumReader = new AsnReader(extValue, AsnEncodingRules.DER);
                                    crl.CrlNumber = (int)crlNumReader.ReadInteger();
                                } catch {
                                    // Ignore errors in parsing CRL number
                                }
                                break;
                        }
                    } catch {
                        // If we can't parse this extension, skip it
                        continue;
                    }
                }
            }
        } catch {
            // If we can't parse extensions at all, that's okay - they're optional
        }

        return crl;
    }

    /// <summary>
    /// Creates the CRL envelope with RSA signature
    /// </summary>
    /// <param name="signingKey">The RSA key to sign with</param>
    /// <returns>The signed and serialized CRL</returns>
    public byte[] SignAndSerialize(RSA signingKey) {
        if (signingKey == null) throw new ArgumentNullException(nameof(signingKey));
        if (_rawTbsCertList == null) throw new InvalidOperationException("TBS CertList data not available");

        // Sign the TBS data
        var signature = signingKey.SignData(_rawTbsCertList, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Create the outer sequence: TBSCertList, SignatureAlgorithm, Signature
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        {
            // TBSCertList (write raw bytes directly)
            writer.WriteEncodedValue(_rawTbsCertList);

            // SignatureAlgorithm
            writer.PushSequence();
            {
                writer.WriteObjectIdentifier(Oid_sha256RSA);
                writer.WriteNull();
            }
            writer.PopSequence();

            // Signature (as BIT STRING)
            writer.WriteBitString(signature, unusedBitCount: 0);
        }
        writer.PopSequence();

        return writer.Encode();
    }

    /// <summary>
    /// Create a CRL from raw DER ASN.1 data (signed CRL structure)
    /// </summary>
    public static CertificateRevocationListSequence Load(byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        // Pass the raw data directly - DecodeTbsCertList will handle
        // both signed CRL and TBSCertList structures
        return new CertificateRevocationListSequence(rawData);
    }

    /// <summary>
    /// Extracts the CRL data
    /// </summary>
    public CertificateRevocationList Extract() => Crl;

    /// <summary>
    /// Helper method to read either UTCTime or GeneralizedTime
    /// Real-world CRLs may use either format
    /// </summary>
    private static DateTimeOffset ReadTime(AsnReader reader) {
        var tag = reader.PeekTag();
        
        // UTCTime (tag 23 = 0x17)
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Universal, isConstructed: false, tagValue: 23))) {
            return reader.ReadUtcTime();
        }
        
        // GeneralizedTime (tag 24 = 0x18)
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.Universal, isConstructed: false, tagValue: 24))) {
            return reader.ReadGeneralizedTime();
        }
        
        // Default to trying both
        try {
            return reader.ReadGeneralizedTime();
        } catch {
            try {
                return reader.ReadUtcTime();
            } catch {
                throw new InvalidOperationException($"Unable to read time value with tag {tag}");
            }
        }
    }
}

/// <summary>
/// DTO that represents a revocation list
/// </summary>
public class CertificateRevocationList
{
    /// <summary>
    /// Issuer CN
    /// </summary>
    public string? IssuerCommonName { get; set; }
    /// <summary>
    /// Issuer O
    /// </summary>
    public string? Organization { get; set; }
    /// <summary>
    /// Issuer C
    /// </summary>
    public string? Country { get; set; }
    /// <summary>
    /// CRL Number (looks like the id of the list)
    /// </summary>
    public int CrlNumber { get; set; }
    /// <summary>
    /// Date when the list becomes effective
    /// </summary>
    public DateTime EffectiveDate { get; set; }
    /// <summary>
    /// When the list should be checked again
    /// </summary>
    public DateTime NextUpdate { get; set; }
    /// <summary>
    /// The Subject Key Identifier of the issuing certificate
    /// </summary>
    public string? AuthorizationKeyId { get; set; }
    /// <summary>
    /// The revoked certificates
    /// </summary>
    public List<RevokedCertificate> Items { get; set; } = new List<RevokedCertificate>();
}

/// <summary>
/// DTO that represents a Revoked certificate inside the <see cref="CertificateRevocationList"/> list
/// </summary>
public class RevokedCertificate
{
    /// <summary>
    /// Certificate serial number (hex format)
    /// </summary>
    public string? SerialNumber { get; set; }
    /// <summary>
    /// Date and time of the revocation
    /// </summary>
    public DateTime RevocationDate { get; set; }
    /// <summary>
    /// Reason that the certificate was revoked
    /// </summary>
    public CRLReasonCode ReasonCode { get; set; }

    /// <summary>
    /// Enum flags for the CRL reason code
    /// </summary>
    public enum CRLReasonCode : byte
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
        /// Superseded - Replaced by a new certificate
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

    /// <summary>
    /// String representation
    /// </summary>
    public override string ToString() => $"{SerialNumber} {RevocationDate}";
}
