using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// QCStatement (rfc3739)
/// <para>
/// Class for standard X509 certificate extension. 
/// This extension have some basics defined in RFC 3739, but the majority of fields are used in EU purposes 
/// and specified in EU standards.
/// <list type="number">
/// <item>ETSI EN 319 412-5 (v2.1.1, 2016-02 or later) <a href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf">en_31941205v020101p.pdf</a></item>
/// <item>ETSI TS 119 495 (v1.1.2, 2018-07 or later) <a href="https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf">ts_119495v010102p.pdf</a></item>
/// </list>
/// </para>
/// <code>
/// qcStatements  EXTENSION ::= {
///        SYNTAX             QCStatements
///        IDENTIFIED BY      id-pe-qcStatements }
/// id-pe-qcStatements     OBJECT IDENTIFIER ::= { id-pe 3 }
/// 
///    QCStatements ::= SEQUENCE OF QCStatement
///    QCStatement ::= SEQUENCE {
///        statementId   QC-STATEMENT.&amp;Id({SupportedStatements}),
///        statementInfo QC-STATEMENT.&amp;Type
///        ({SupportedStatements}{@statementId}) OPTIONAL }
/// 
///    SupportedStatements QC-STATEMENT ::= { qcStatement-1,...}
/// </code>
/// </summary>
public class QualifiedCertificateStatementsExtension : X509Extension
{
    /// <summary>
    /// Qualified Certificate Statements Oid (X509 v3)
    /// </summary>
    public const string Oid_QC_Statements = "1.3.6.1.5.5.7.1.3";

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="isCompliant"><b>QcCompliant</b>. True is the cert is European Qualified Certificate otherwize false</param>
    /// <param name="limit"><b>QcLimitValue</b>. Monetary value </param>
    /// <param name="retentionPeriod"><b>QcRetentionPeriod</b></param>
    /// <param name="isQSCD"><b>QcSSCD</b></param>
    /// <param name="pdsLocations"><b>QcPds</b></param>
    /// <param name="type"><b>QcType</b></param>
    /// <param name="psd2"><b>PSD2 QcStatement</b></param>
    /// <param name="critical"></param>
    public QualifiedCertificateStatementsExtension(bool isCompliant, QcMonetaryValue limit, int retentionPeriod, bool isQSCD, IEnumerable<PdsLocation> pdsLocations, QcTypeIdentifiers type, Psd2Attributes psd2, bool critical) {
        Oid = new Oid(Oid_QC_Statements, "Qualified Certificate Statements");
        Critical = critical;
        RawData = EncodeExtension(isCompliant, limit, retentionPeriod, isQSCD, pdsLocations, type, psd2);
        _Statements = new QualifiedCertificateStatements(isCompliant, limit, retentionPeriod, isQSCD, pdsLocations, type, psd2);
        _decoded = true;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public QualifiedCertificateStatementsExtension(AsnEncodedData encodedExtension, bool critical) : base(encodedExtension, critical) {
    }

    private bool _decoded = false;
    private QualifiedCertificateStatements _Statements = null!;

    /// <summary>
    /// European Qualified Certificate Statements.
    /// </summary>
    public QualifiedCertificateStatements Statements {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _Statements;
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

    private static byte[] EncodeExtension(bool isCompliant, QcMonetaryValue? limit, int retentionPeriod, bool isQSCD, IEnumerable<PdsLocation>? pdsLocations, QcTypeIdentifiers type, Psd2Attributes? psd2) {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence(); // QCStatements
        {
            QcComplianceStatement.Encode(writer, isCompliant);
            QcRetentionPeriodStatement.Encode(writer, retentionPeriod);
            QcLimitValueStatement.Encode(writer, limit);
            QcSSCDStatement.Encode(writer, isQSCD);
            QcTypeStatement.Encode(writer, type);
            QcPdsStatement.Encode(writer, pdsLocations);
            Psd2QcStatement.Encode(writer, psd2);
        }
        writer.PopSequence();

        return writer.Encode();
    }

    private void DecodeExtension() {
        _Statements = new QualifiedCertificateStatements();
        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            var mainSeq = reader.ReadSequence();
            while (mainSeq.HasData) {
                var qcSeq = mainSeq;
                var tag = mainSeq.PeekTag();
                // the next element can be either a sequence (if statementInfo is present) or an OID (if statementInfo is absent)
                if (tag.HasSameClassAndValue(Asn1Tag.Sequence)) {
                    qcSeq = mainSeq.ReadSequence();
                } else if (!tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier)) {
                    throw new InvalidOperationException($"Unexpected ASN.1 tag {tag} while decoding QCStatement. Expected SEQUENCE or OBJECT IDENTIFIER.");
                }

                var oid = qcSeq.ReadObjectIdentifier();

                switch (oid) {
                    case QcComplianceStatement.Oid_QcCompliance:
                        _Statements.IsCompliant = true;
                        break;
                    case QcLimitValueStatement.Oid_QcLimitValue:
                        _Statements.LimitValue = QcLimitValueStatement.Decode(qcSeq);
                        break;
                    case QcRetentionPeriodStatement.Oid_QcRetentionPeriod:
                        _Statements.RetentionPeriod = QcRetentionPeriodStatement.Decode(qcSeq);
                        break;
                    case QcSSCDStatement.Oid_QcSSCD:
                        _Statements.IsQSCD = true;
                        break;
                    case QcPdsStatement.Oid_QcPds:
                        _Statements.PdsLocations = QcPdsStatement.Decode(qcSeq);
                        break;
                    case QcTypeStatement.Oid_QcType:
                        _Statements.Type = QcTypeStatement.Decode(qcSeq);
                        break;
                    case Psd2QcStatement.Oid_PSD2_QcStatement:
                        _Statements.Psd2Type = Psd2QcStatement.Decode(qcSeq);
                        break;
                }
            }

            _decoded = true;
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode QualifiedCertificateStatements extension.", ex);
        }
    }
}

/// <summary>
/// <b>QcCompliance</b>. QCStatement claiming that the certificate is a European Qualified Certificate
/// </summary>
/// <remarks>
/// esi4-qcStatement-1 QC-STATEMENT ::= { SYNTAX NULL IDENTIFIED BY id-etsi-qcs-QcCompliance }
/// id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::= { id-etsi-qcs 1 } 
/// </remarks>
public static class QcComplianceStatement
{
    /// <summary>
    /// id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcCompliance(1)}
    /// </summary>
    public const string Oid_QcCompliance = "0.4.0.1862.1.1";

    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="isCompliant"></param>
    public static void Encode(AsnWriter writer, bool isCompliant) {
        if (!isCompliant) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcCompliance);
        }
        writer.PopSequence();
    }
}

/// <summary>
/// <b>QcRetentionPeriod</b>. QCStatement indicating the duration of the retention period of
/// material information
/// </summary>
/// <remarks>
/// <code>
/// esi4-qcStatement-3 QC-STATEMENT ::= { SYNTAX QcRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }
/// QcRetentionPeriod::= INTEGER
/// id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs 3 } 
/// </code>
/// </remarks>
public static class QcRetentionPeriodStatement
{
    /// <summary>
    /// id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcRetentionPeriod(3)}
    /// </summary>
    public const string Oid_QcRetentionPeriod = "0.4.0.1862.1.3";

    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="retentionPeriod"></param>
    public static void Encode(AsnWriter writer, int retentionPeriod) {
        if (retentionPeriod <= 0) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcRetentionPeriod);
            writer.WriteInteger(retentionPeriod);
        }
        writer.PopSequence();
    }

    /// <summary>
    /// Deserializes the raw data into the statement.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static int Decode(AsnReader reader) => reader.HasData ? (int)reader.ReadInteger() : default;
}

/// <summary>
/// <b>QcSSCD</b>. QCStatement claiming that the private key related to the certified
/// public key resides in a QSCD
/// </summary>
/// <remarks>
/// <code>
/// esi4-qcStatement-4 QC-STATEMENT ::= { SYNTAX NULL IDENTIFIED BY id-etsi-qcs-QcSSCD }
/// id-etsi-qcs-QcSSCD OBJECT IDENTIFIER ::= { id-etsi-qcs 4 } 
/// </code>
/// </remarks>
public static class QcSSCDStatement
{
    /// <summary>
    /// id-etsi-qcs-QcSSCD OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcSSCD(4)}
    /// </summary>
    public const string Oid_QcSSCD = "0.4.0.1862.1.4";

    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="isQSCD"></param>
    public static void Encode(AsnWriter writer, bool isQSCD) {
        if (!isQSCD) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcSSCD);
        }
        writer.PopSequence();
    }
}

/// <summary>
/// <b>QcLimitValue</b>. QCStatement regarding limits on the value of transactions 
/// material information
/// </summary>
public static class QcLimitValueStatement
{
    /// <summary>
    /// id-etsi-qcs-QcLimitValue OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcLimitValue(2)}
    /// </summary>
    public const string Oid_QcLimitValue = "0.4.0.1862.1.2";

    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="monetaryValue"></param>
    public static void Encode(AsnWriter writer, QcMonetaryValue? monetaryValue) {
        if (monetaryValue is null) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcLimitValue);
            writer.PushSequence(); // MonetaryValue
            {
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, monetaryValue.CurrencyCode);
                // Derive amount (BigInteger mantissa) and exponent from decimal value per RFC 3739
                // decimal.GetBits returns [lo, mid, hi, flags]; flags bits 16-23 hold the scale
                var rawBits = decimal.GetBits(monetaryValue.Value);
                int scale = (rawBits[3] >> 16) & 0x7F;
                bool isNegative = (rawBits[3] & unchecked((int)0x80000000)) != 0;
                // Build the 96-bit mantissa as a little-endian byte array for BigInteger
                // (12 bytes: lo 4 + mid 4 + hi 4, plus a 0x00 to ensure positive interpretation)
                var mantissaBytes = new byte[13];
                System.Buffer.BlockCopy(rawBits, 0, mantissaBytes, 0, 12);
                // mantissaBytes[12] = 0x00 already (ensures the BigInteger is treated as positive)
                var mantissa = new BigInteger(mantissaBytes, isUnsigned: true, isBigEndian: false);
                if (isNegative) mantissa = -mantissa;
                int exponent = -scale;
                writer.WriteInteger(mantissa);
                writer.WriteInteger(exponent);
            }
            writer.PopSequence();
        }
        writer.PopSequence();
    }
    /// <summary>
    /// Deserializes the raw data into the statement.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static QcMonetaryValue? Decode(AsnReader reader) {
        if (!reader.HasData) {
            return null;
        }
        var moneySeq = reader.ReadSequence();
        string currency = moneySeq.ReadCharacterString(UniversalTagNumber.PrintableString);
        BigInteger amount = moneySeq.ReadInteger();
        int exponent = 0;
        if (moneySeq.HasData) {
            exponent = (int)moneySeq.ReadInteger();
        }
        // Apply exponent via decimal integer scaling to avoid floating-point imprecision
        decimal value = (decimal)amount;
        if (exponent > 0) {
            for (int i = 0; i < exponent; i++) value *= 10m;
        } else {
            for (int i = 0; i > exponent; i--) value /= 10m;
        }
        return new QcMonetaryValue { Value = value, CurrencyCode = currency };

    }
}

/// <summary>
/// <b>QcPDS</b>. This QCStatement holds URLs to PKI Disclosure Statements (PDS) in accordance with Annex A of ETSI EN 319 411-1 [i.10]
/// </summary>
/// <remarks>
/// <code>
/// esi4-qcStatement-5 QC-STATEMENT ::= { SYNTAX QcPdsLocations IDENTIFIED BY id-etsi-qcs-QcPds }
/// QcPdsLocations ::= SEQUENCE OF PdsLocation
/// id-etsi-qcs-QcPds OBJECT IDENTIFIER ::= { id-etsi-qcs 5 } 
/// </code>
/// </remarks>
public static class QcPdsStatement
{
    /// <summary>
    /// id-etsi-qcs-QcPds OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcPds(5)}
    /// </summary>
    public const string Oid_QcPds = "0.4.0.1862.1.5";

    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="pdsLocations"></param>
    public static void Encode(AsnWriter writer, IEnumerable<PdsLocation>? pdsLocations) {
        if (pdsLocations is null || !pdsLocations.Any()) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcPds);
            writer.PushSequence(); // PdsLocations
            {
                foreach (var location in pdsLocations) {
                    writer.PushSequence(); // PdsLocation
                    {
                        writer.WriteCharacterString(UniversalTagNumber.IA5String, location.Url);
                        if (!string.IsNullOrEmpty(location.Language)) {
                            writer.WriteCharacterString(UniversalTagNumber.PrintableString, location.Language);
                        }
                    }
                    writer.PopSequence();
                }
            }
            writer.PopSequence();
        }
        writer.PopSequence();
    }
    /// <summary>
    /// Deserializes the raw data into the statement.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static PdsLocation[] Decode(AsnReader reader) {
        if (!reader.HasData) {
            return [];
        }
        var pdsSeq = reader.ReadSequence();
        var locations = new List<PdsLocation>();
        while (pdsSeq.HasData) {
            var locSeq = pdsSeq.ReadSequence();
            string url = locSeq.ReadCharacterString(UniversalTagNumber.IA5String);
            string? language = locSeq.HasData ? locSeq.ReadCharacterString(UniversalTagNumber.PrintableString) : null;
            locations.Add(new PdsLocation { Url = url, Language = language });
        }
        return [.. locations];
    }
}

/// <summary>
/// <b>QcType</b>. Specifies the type of qualified certificate - electronic signature, seal, or website authentication
/// </summary>
public static class QcTypeStatement
{
    /// <summary>
    /// id-etsi-qcs-QcType OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcType(6)}
    /// </summary>
    public const string Oid_QcType = "0.4.0.1862.1.6";

    /// <summary>
    /// id-etsi-qct-esign OBJECT IDENTIFIER ::= { id-etsi-qct 1 }
    /// </summary>
    public const string Oid_QcType_eSign = "0.4.0.1862.1.6.1";

    /// <summary>
    /// id-etsi-qct-eseal OBJECT IDENTIFIER ::= { id-etsi-qct 2 }
    /// </summary>
    public const string Oid_QcType_eSeal = "0.4.0.1862.1.6.2";

    /// <summary>
    /// id-etsi-qct-web OBJECT IDENTIFIER ::= { id-etsi-qct 3 }
    /// </summary>
    public const string Oid_QcType_Web = "0.4.0.1862.1.6.3";


    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="type"></param>
    public static void Encode(AsnWriter writer, QcTypeIdentifiers type) {
        if (type == QcTypeIdentifiers.None) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Oid_QcType);
            writer.PushSequence(); // QcTypes
            {
                switch (type) {
                    case QcTypeIdentifiers.eSign:
                        writer.WriteObjectIdentifier(Oid_QcType_eSign);
                        break;
                    case QcTypeIdentifiers.eSeal:
                        writer.WriteObjectIdentifier(Oid_QcType_eSeal);
                        break;
                    case QcTypeIdentifiers.Web:
                        writer.WriteObjectIdentifier(Oid_QcType_Web);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(type), type, "Invalid QcTypeIdentifier value.");
                }
            }
            writer.PopSequence();
        }
        writer.PopSequence();
    }
    /// <summary>
    /// Deserializes the raw data into the statement.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static QcTypeIdentifiers Decode(AsnReader reader) {
        if (!reader.HasData) {
            return QcTypeIdentifiers.None;
        }
        var typeSeq = reader.ReadSequence();
        while (typeSeq.HasData) {
            var typeOid = typeSeq.ReadObjectIdentifier();
            if (typeOid == Oid_QcType_eSign)
                return QcTypeIdentifiers.eSign;
            else if (typeOid == Oid_QcType_eSeal)
                return QcTypeIdentifiers.eSeal;
            else if (typeOid == Oid_QcType_Web)
                return QcTypeIdentifiers.Web;
        }
        return QcTypeIdentifiers.None;
    }
}

/// <summary>
/// <b>Psd2QcStatement</b>. PSD2 specific QC statement
/// </summary>
public static class Psd2QcStatement
{
    /// <summary>
    /// PSD2 QC statement OID
    /// </summary>
    public const string Oid_PSD2_QcStatement = "0.4.0.19495.2";

    /// <summary>
    /// Base OID for PSD2 roles
    /// </summary>
    public const string Oid_PSD2_Roles = "0.4.0.19495.1";

    /// <summary>
    /// PSP Account Servicing role
    /// </summary>
    public const string Oid_PSD2_Roles_PSP_AS = Oid_PSD2_Roles + ".1";

    /// <summary>
    /// PSP Payment Initiation role
    /// </summary>
    public const string Oid_PSD2_Roles_PSP_PI = Oid_PSD2_Roles + ".2";

    /// <summary>
    /// PSP Account Information role
    /// </summary>
    public const string Oid_PSD2_Roles_PSP_AI = Oid_PSD2_Roles + ".3";

    /// <summary>
    /// PSP Issuing of Card-Based Payment Instruments role
    /// </summary>
    public const string Oid_PSD2_Roles_PSP_IC = Oid_PSD2_Roles + ".4";


    /// <summary>
    /// Encode statement sequence.
    /// </summary>
    /// <param name="writer"></param>
    /// <param name="psd2"></param>
    public static void Encode(AsnWriter writer, Psd2Attributes? psd2) {
        if (psd2 == null) {
            return;
        }
        writer.PushSequence(); // QCStatement
        {
            writer.WriteObjectIdentifier(Psd2QcStatement.Oid_PSD2_QcStatement);
            writer.PushSequence(); // PSD2QcType
            {
                // Roles of PSP
                writer.PushSequence(); // RolesOfPSP
                {
                    if (psd2.HasAccountServicing) {
                        writer.PushSequence(); // RoleOfPSP
                        {
                            writer.WriteObjectIdentifier(Psd2QcStatement.Oid_PSD2_Roles_PSP_AS);
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "PSP_AS");
                        }
                        writer.PopSequence();
                    }
                    if (psd2.HasPaymentInitiation) {
                        writer.PushSequence(); // RoleOfPSP
                        {
                            writer.WriteObjectIdentifier(Psd2QcStatement.Oid_PSD2_Roles_PSP_PI);
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "PSP_PI");
                        }
                        writer.PopSequence();
                    }
                    if (psd2.HasAccountInformation) {
                        writer.PushSequence(); // RoleOfPSP
                        {
                            writer.WriteObjectIdentifier(Psd2QcStatement.Oid_PSD2_Roles_PSP_AI);
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "PSP_AI");
                        }
                        writer.PopSequence();
                    }
                    if (psd2.HasIssuingOfCardBasedPaymentInstruments) {
                        writer.PushSequence(); // RoleOfPSP
                        {
                            writer.WriteObjectIdentifier(Psd2QcStatement.Oid_PSD2_Roles_PSP_IC);
                            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "PSP_IC");
                        }
                        writer.PopSequence();
                    }
                }
                writer.PopSequence();

                // NCAName
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, psd2.AuthorityName ?? string.Empty);

                // NCAId
                writer.WriteCharacterString(UniversalTagNumber.UTF8String, psd2.AuthorizationId.ToString());
            }
            writer.PopSequence();
        }
        writer.PopSequence();
    }
    /// <summary>
    /// Deserializes the raw data into the statement.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public static Psd2Attributes? Decode(AsnReader reader) {
        if (!reader.HasData) {
            return null;
        }
        var psd2 = new Psd2Attributes();
        var psd2Seq = reader.ReadSequence();

        // Roles
        if (psd2Seq.HasData) {
            var rolesSeq = psd2Seq.ReadSequence();
            while (rolesSeq.HasData) {
                var roleSeq = rolesSeq.ReadSequence();
                var roleOid = roleSeq.ReadObjectIdentifier();
                var roleName = roleSeq.ReadCharacterString(UniversalTagNumber.UTF8String);

                // Map OID back to role name
                switch (roleOid) {
                    case Oid_PSD2_Roles_PSP_AS:
                        psd2.HasAccountServicing = true;
                        break;
                    case Oid_PSD2_Roles_PSP_PI:
                        psd2.HasPaymentInitiation = true;
                        break;
                    case Oid_PSD2_Roles_PSP_AI:
                        psd2.HasAccountInformation = true;
                        break;
                    case Oid_PSD2_Roles_PSP_IC:
                        psd2.HasIssuingOfCardBasedPaymentInstruments = true;
                        break;
                }
            }
        }

        // NCAName
        if (psd2Seq.HasData) {
            psd2.AuthorityName = psd2Seq.ReadCharacterString(UniversalTagNumber.UTF8String);
        }

        // NCAId
        if (psd2Seq.HasData) {
            var ncaIdStr = psd2Seq.ReadCharacterString(UniversalTagNumber.UTF8String);
            psd2.AuthorizationId = NCAId.Parse(ncaIdStr);
        }

        return psd2;
    }
}

/// <summary>
/// QC Type Identifiers for certificate types
/// </summary>
public enum QcTypeIdentifiers
{
    /// <summary>
    /// No specific type
    /// </summary>
    None = 0,
    /// <summary>
    /// Certificate for <b>electronic signatures</b> as defined in Regulation (EU) No 910/2014
    /// (id-etsi-qct-esign)
    /// </summary>
    eSign = 1,
    /// <summary>
    /// Certificate for <b>electronic seals</b> as defined in Regulation (EU) No 910/2014
    /// (id-etsi-qct-eseal)
    /// </summary>
    eSeal = 2,
    /// <summary>
    /// Certificate for <b>website authentication</b> as defined in Regulation (EU) No 910/2014
    /// (id-etsi-qct-web)
    /// </summary>
    Web = 3,
}

/// <summary>
/// holds the URL to a PKI Disclosure Statement (PDS) in accordance with Annex A of ETSI EN 319 411-1 
/// </summary>
public class PdsLocation
{
    /// <summary>
    /// The url.
    /// </summary>
    public string Url { get; set; } = null!;
    /// <summary>
    /// ISO 639-1 language code
    /// </summary>
    public string? Language { get; set; }
    /// <inheritdoc />
    public override string ToString() => $"{Url} ({Language})";
}

/// <summary>
/// Value representing money.
/// </summary>
public class QcMonetaryValue
{
    /// <summary>
    ///  value = amount * 10^exponent
    /// </summary>
    public decimal Value { get; set; }
    /// <summary>
    /// Alphabetic or numeric currency code as defined in ISO 4217 
    /// </summary>
    public string CurrencyCode { get; set; } = null!;
    /// <inheritdoc />
    public override string ToString() => $"{Value} {CurrencyCode}";
}

/// <summary>
/// DTO encapsulating all statements found inside a <see cref="QualifiedCertificateStatementsExtension"/>
/// </summary>
public class QualifiedCertificateStatements
{
    internal QualifiedCertificateStatements() { }
    /// <summary>
    ///  DTO encapsulating all statements found inside a <see cref="QualifiedCertificateStatementsExtension"/>
    /// </summary>
    /// <param name="isCompliant"><b>QcCompliant</b>. True is the cert is European Qualified Certificate otherwize false</param>
    /// <param name="limit"><b>QcLimitValue</b>. Monetary value </param>
    /// <param name="retentionPeriod"><b>QcRetentionPeriod</b></param>
    /// <param name="isQSCD"><b>QcSSCD</b></param>
    /// <param name="pdsLocations"><b>QcPds</b></param>
    /// <param name="type"><b>QcType</b></param>
    /// <param name="psd2"><b>PSD2 QcStatement</b></param>
    public QualifiedCertificateStatements(bool isCompliant, QcMonetaryValue? limit, int retentionPeriod, bool isQSCD, IEnumerable<PdsLocation>? pdsLocations, QcTypeIdentifiers type, Psd2Attributes? psd2) {
        IsCompliant = isCompliant;
        LimitValue = limit;
        RetentionPeriod = retentionPeriod;
        IsQSCD = isQSCD;
        PdsLocations = pdsLocations?.ToArray() ?? [];
        Type = type;
        Psd2Type = psd2;
    }
    /// <summary>
    /// European Qualified Certificate.
    /// </summary>
    public bool IsCompliant { get; internal set; }

    /// <summary>
    /// <b>QcLimitValue</b>. QCStatement regarding limits on the value of transactions 
    /// </summary>
    public QcMonetaryValue? LimitValue { get; internal set; }
    /// <summary>
    /// <b>QcRetentionPeriod</b>. QCStatement indicating the duration of the retention period of
    /// material information
    /// </summary>
    public int RetentionPeriod { get; internal set; }

    /// <summary>
    /// <b>QcSSCD</b>. QCStatement claiming that the private key related to the certified
    /// public key resides in a QSCD
    /// </summary>
    public bool IsQSCD { get; internal set; }

    ///<b>QcPDS</b>. This QCStatement holds URLs to PKI Disclosure Statements (PDS) in accordance with Annex A of ETSI EN 319 411-1 [i.10]. 
    public PdsLocation[] PdsLocations { get; internal set; } = [];

    /// <summary>
    /// <b>QcType</b>. claiming that the certificate is a certificate of a particular type
    /// </summary>
    public QcTypeIdentifiers Type { get; internal set; }

    /// <summary>
    /// <b>Psd2QcType</b>. Attributes specific to the PSD2 directive.
    /// </summary>
    public Psd2Attributes? Psd2Type { get; internal set; }
}