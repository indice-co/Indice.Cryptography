using System;
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
/// QCStatement (rfc3739)
/// 
/// Class for standard X509 certificate extension. 
/// This extension have some basics defined in RFC 3739, but the majority of fields are used in EU purposes 
/// and specified in EU standards.
/// ETSI EN 319 412-5 (v2.1.1, 2016-02 or later)
/// https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.01.01_60/en_31941205v020101p.pdf
/// ETSI TS 119 495 (v1.1.2, 2018-07 or later)
/// https://www.etsi.org/deliver/etsi_ts/119400_119499/119495/01.01.02_60/ts_119495v010102p.pdf
/// 
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
        var statements = new List<DerAsnSequence>();
        if (isCompliant) {
            statements.Add(new QcComplianceStatement());
        }
        if (retentionPeriod > 0) {
            statements.Add(new QcRetentionPeriodStatement(retentionPeriod));
        }
        if (limit != null) {
            statements.Add(new QcLimitValueStatement(limit));
        }
        if (isQSCD) {
            statements.Add(new QcSSCDStatement());
        }
        statements.Add(new QcTypeStatement(type));
        if (pdsLocations?.Any() == true) {
            statements.Add(new QcPdsStatement(pdsLocations));
        }
        if (psd2 != null) {
            statements.Add(new Psd2QcStatement(psd2));
        }
        RawData = DerConvert.Encode(new DerAsnSequence(statements.ToArray())).ToArray();
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

    private QualifiedCertificateStatements _Statements;

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

    private void DecodeExtension() {
        _Statements = new QualifiedCertificateStatements();
        var root = DerConvert.Decode(RawData) as DerAsnSequence;
        if (root.Value[0] is DerAsnSequence) {
            foreach (var sequence in root.Value.OfType<DerAsnSequence>()) {
                if (sequence.Value[0] is DerAsnObjectIdentifier oid) {
                    switch (oid.Value.ToOidString()) {
                        case QcComplianceStatement.Oid_QcCompliance:
                            _Statements.IsCompliant = new QcComplianceStatement(sequence.Value).Extract(); break;
                        case QcLimitValueStatement.Oid_QcLimitValue:
                            _Statements.LimitValue = new QcLimitValueStatement(sequence.Value).Extract(); break;
                        case QcRetentionPeriodStatement.Oid_QcRetentionPeriod:
                            _Statements.RetentionPeriod = new QcRetentionPeriodStatement(sequence.Value).Extract(); break;
                        case QcSSCDStatement.Oid_QcSSCD:
                            _Statements.IsQSCD = new QcSSCDStatement(sequence.Value).Extract(); break;
                        case QcPdsStatement.Oid_QcPds:
                            _Statements.PdsLocations = new QcPdsStatement(sequence.Value).Extract(); break;
                        case QcTypeStatement.Oid_QcType:
                            _Statements.Type = new QcTypeStatement(sequence.Value).Extract(); break;
                        case Psd2QcStatement.Oid_PSD2_QcStatement:
                            _Statements.Psd2Type = new Psd2QcStatement(sequence.Value).Extract(); break;
                        default: break;
                    }

                }
            }
        } else if (root.Value[0] is DerAsnObjectIdentifier oid &&
                   Psd2QcStatement.Oid_PSD2_QcStatement.Equals(oid.Value.ToOidString())) {
            _Statements.Psd2Type = new Psd2QcStatement(root.Value).Extract();
        }
        _decoded = true;
    }
}

/// <summary>
/// Qualified Certificate Statements for PSD2
/// etsi-psd2-qcStatement QC-STATEMENT ::= {SYNTAX PSD2QcType IDENTIFIED BY id-etsi-psd2-qcStatement } 
/// </summary>
public class Psd2QcStatement : DerAsnSequence
{
    /// <summary>
    /// id-etsi-psd2-qcStatement OBJECT IDENTIFIER ::=  { itu-t(0) identified-organization(4) etsi(0) psd2(19495) qcstatement(2) } 
    /// </summary>
    public const string Oid_PSD2_QcStatement = "0.4.0.19495.2";
    private const string Oid_PSD2_Roles = "0.4.0.19495.1";
    private const string Oid_PSD2_Roles_PSP_AS = Oid_PSD2_Roles + ".1";
    private const string Oid_PSD2_Roles_PSP_PI = Oid_PSD2_Roles + ".2";
    private const string Oid_PSD2_Roles_PSP_AI = Oid_PSD2_Roles + ".3";
    private const string Oid_PSD2_Roles_PSP_IC = Oid_PSD2_Roles + ".4";

    private static readonly Dictionary<string, string> roleId2NameMap = new Dictionary<string, string> {
        ["PSP_AS"] = Oid_PSD2_Roles_PSP_AS,
        ["PSP_PI"] = Oid_PSD2_Roles_PSP_PI,
        ["PSP_AI"] = Oid_PSD2_Roles_PSP_AI,
        ["PSP_IC"] = Oid_PSD2_Roles_PSP_IC
    };

    private static string GetPsd2Oid(string roleName) {
        return roleId2NameMap[roleName];
    }

    /// <summary>
    /// Constructs the QcStatement from <see cref="Psd2Attributes "/>.
    /// </summary>
    /// <param name="psd2"></param>
    public Psd2QcStatement(Psd2Attributes psd2) : base(Array.Empty<DerAsnType>()) {
        var rolesList = new List<DerAsnSequence>();
        foreach (var roleName in psd2.Roles) {
            var id = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, GetPsd2Oid(roleName).OidToArray());
            var name = new DerAsnUtf8String(roleName);
            var role = new DerAsnSequence(new DerAsnType[] { id, name });
            rolesList.Add(role);
        }
        var rolesOfPSP = new DerAsnSequence(rolesList.ToArray()); //RolesOfPSP ::= SEQUENCE OF RoleOfPSP 
        var ncaName = new DerAsnUtf8String(psd2.AuthorityName);
        var ncaId = new DerAsnUtf8String(psd2.AuthorizationId.ToString());

        var typeSequence = new DerAsnSequence(new DerAsnType[] { rolesOfPSP, ncaName, ncaId });

        var psd2QstatementOid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_PSD2_QcStatement.OidToArray());
        Value = new DerAsnType[] { psd2QstatementOid, typeSequence };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public Psd2QcStatement(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the raw data into the concrete class <see cref="Psd2Attributes"/>.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public Psd2Attributes Extract() {
        var attributes = new Psd2Attributes();
        var typeSequence = Value.Where(x => x is DerAsnSequence).FirstOrDefault() as DerAsnSequence;
        var roleSequence = typeSequence?.Value.Where(x => x is DerAsnSequence).FirstOrDefault() as DerAsnSequence;
        var ncaName = typeSequence?.Value[1] as DerAsnUtf8String;
        var ncaId = typeSequence?.Value[2] as DerAsnUtf8String;
        attributes.AuthorityName = ncaName?.Value;
        attributes.AuthorizationId = NCAId.Parse(ncaId!.Value, false);
        foreach (var item in roleSequence!.Value) {
            if (!(item is DerAsnSequence)) {
                continue;
            }
            var role = item as DerAsnSequence;
            var roleOid = role!.Value[0] as DerAsnObjectIdentifier;
            var roleOidString = string.Join(".", roleOid!.Value);
            switch (roleOidString) {
                case Oid_PSD2_Roles_PSP_AS: attributes.HasAccountServicing = true; break;
                case Oid_PSD2_Roles_PSP_PI: attributes.HasPaymentInitiation = true; break;
                case Oid_PSD2_Roles_PSP_AI: attributes.HasAccountInformation = true; break;
                case Oid_PSD2_Roles_PSP_IC: attributes.HasIssuingOfCardBasedPaymentInstruments = true; break;
            }
        }
        return attributes;
    }
}

/// <summary>
/// QCStatement claiming that the certificate is a EU qualified
/// certificate or a certificate being qualified within a defined legal
/// framework from an identified country or set of countries
/// </summary>
/// <remarks>
/// esi4-qcStatement-1 QC-STATEMENT ::= { IDENTIFIED BY id-etsi-qcs-QcCompliance }
/// id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::= { id-etsi-qcs 1 }
/// </remarks>
public class QcComplianceStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcCompliance OBJECT IDENTIFIER ::=  { itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcstatement(1) } 
    /// </summary>
    public const string Oid_QcCompliance = "0.4.0.1862.1.1";

    /// <summary>
    /// Constructs the QcStatement to be added to a certificate.
    /// </summary>
    public QcComplianceStatement() : base(Array.Empty<DerAsnType>()) {
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcCompliance.OidToArray());
        Value = new DerAsnType[] { oid };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcComplianceStatement(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Nothing to do. This always returns true.
    /// if this statement is present this automatically means the cert is qualified.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public bool Extract() {
        var isQualified = true;
        return isQualified;
    }
}


/// <summary>
/// <b>QcRetentionPeriod</b>. QCStatement indicating the duration of the retention period of
/// material information
/// </summary>
/// <remarks>
/// esi4-qcStatement-3 QC-STATEMENT ::= { SYNTAX QcEuRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }
///  QcEuRetentionPeriod ::= INTEGER
///  id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs 3 } 
/// </remarks>
public class QcRetentionPeriodStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcRetentionPeriod(3)}
    /// </summary>
    public const string Oid_QcRetentionPeriod = "0.4.0.1862.1.3";

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcRetentionPeriodStatement(int retentionPeriod) : base(Array.Empty<DerAsnType>()) {
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcRetentionPeriod.OidToArray());
        Value = new DerAsnType[] { oid, new DerAsnInteger(new BigInteger(retentionPeriod)) };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcRetentionPeriodStatement(DerAsnType[] value) : base(value) {

    }


    /// <summary>
    /// Deserializes the data into a concrete type
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public int Extract() {
        var retention = Value.OfType<DerAsnInteger>().FirstOrDefault();
        return retention != null ? (int)retention.Value : 0;
    }
}

/// <summary>
/// <b>QcSSCD</b>. This Qcstatement declares that the private key related to the certified public key resides in a Qualified
/// Signature/Seal Creation Device(QSCD)
/// </summary>
/// <remarks>
/// esi4-qcStatement-3 QC-STATEMENT ::= { SYNTAX QcEuRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }
///  QcEuRetentionPeriod ::= INTEGER
///  id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs 3 } 
/// </remarks>
public class QcSSCDStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcSSCD(4)}
    /// </summary>
    public const string Oid_QcSSCD = "0.4.0.1862.1.4";

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcSSCDStatement() : base(Array.Empty<DerAsnType>()) {
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcSSCD.OidToArray());
        Value = new DerAsnType[] { oid };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcSSCDStatement(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the data into a concrete type
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public bool Extract() { return true; }
}


/// <summary>
/// <b>QcLimitValue</b>. QCStatement regarding limits on the value of transactions 
/// material information
/// </summary>
/// <remarks>
/// esi4-qcStatement-2 QC-STATEMENT ::= { SYNTAX QcEuLimitValue IDENTIFIED
///     BY id-etsi-qcs-QcLimitValue }
///     QcEuLimitValue ::= MonetaryValue
///     MonetaryValue::= SEQUENCE {
///          currency Iso4217CurrencyCode,
///          amount INTEGER,
///          exponent INTEGER}
///       -- value = amount * 10^exponent
///     Iso4217CurrencyCode ::= CHOICE {
///          alphabetic PrintableString (SIZE (3)), -- Recommended
///          numeric INTEGER (1..999) }
///          -- Alphabetic or numeric currency code as defined in ISO 4217
///          -- It is recommended that the Alphabetic form is used
///     id-etsi-qcs-QcLimitValue OBJECT IDENTIFIER ::= { id-etsi-qcs 2 } 
/// </remarks>
public class QcLimitValueStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcLimitValue OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcLimitValue(2)}
    /// </summary>
    public const string Oid_QcLimitValue = "0.4.0.1862.1.2";

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcLimitValueStatement(QcMonetaryValue limit)
        : this(limit.Value, limit.CurrencyCode) {
    }

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcLimitValueStatement(decimal limitValue, string currenyCode) : base(Array.Empty<DerAsnType>()) {
        var parts = decimal.GetBits(limitValue);
        var scale = (byte)((parts[3] >> 16) & 0x7F);
        var amount = ((BigInteger)limitValue) * (int)Math.Pow(10.0, scale);
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcLimitValue.OidToArray());
        Value = new DerAsnType[] { oid, new DerAsnSequence(new DerAsnType[] {
            new DerAsnPrintableString(currenyCode.Substring(0, 3)),
            new DerAsnInteger(amount),
            new DerAsnInteger(new BigInteger(-scale)),
        }) };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcLimitValueStatement(DerAsnType[] value) : base(value) {

    }


    /// <summary>
    /// Deserializes the data into a concrete type
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public QcMonetaryValue Extract() {
        var sequence = Value.OfType<DerAsnSequence>().FirstOrDefault();
        if (sequence == null)
            return null;

        var monetaryValue = new QcMonetaryValue();
        if (sequence.Value[0] is DerAsnPrintableString printableString) {
            monetaryValue.CurrencyCode = printableString.Value;
        } else if (sequence.Value[0] is DerAsnInteger integer) {
            monetaryValue.CurrencyCode = ((int)integer.Value).ToString();
        }
        var amount = ((DerAsnInteger)(sequence.Value[1])).Value;
        var exponent = (int)((DerAsnInteger)(sequence.Value[2])).Value;
        monetaryValue.Value = (decimal)amount * (decimal)Math.Pow(10.0, exponent);
        return monetaryValue;
    }

}


/// <summary>
/// <b>QcPds</b>. This QCStatement holds URLs to PKI Disclosure Statements (PDS) in accordance with Annex A of ETSI EN 319 411-1 [i.10]. 
/// </summary>
/// <remarks>
/// esi4-qcStatement-5 QC-STATEMENT ::= { SYNTAX QcEuPDS IDENTIFIED BY id-etsi-qcs-QcPDS }
///     
/// QcEuPDS ::= PdsLocations
/// 
/// PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation
/// 
/// PdsLocation::= SEQUENCE {
///     url        IA5String,
///     language   PrintableString (SIZE(2))} --ISO 639-1 language code
///     
/// id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 } 
/// </remarks>
public class QcPdsStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcPDS(5)}
    /// </summary>
    public const string Oid_QcPds = "0.4.0.1862.1.5";

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcPdsStatement(IEnumerable<PdsLocation> pdsLocations) : base(Array.Empty<DerAsnType>()) {
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcPds.OidToArray());
        var sequence = new List<DerAsnType>();
        foreach (var item in pdsLocations) {
            var pdsSequense = new DerAsnSequence(new DerAsnType[] {
                new DerAsnIa5String(item.Url),
                new DerAsnPrintableString(item.Language)
            });
            sequence.Add(pdsSequense);
        }
        Value = new DerAsnType[] { oid, new DerAsnSequence(sequence.ToArray()) };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcPdsStatement(DerAsnType[] value) : base(value) {

    }


    /// <summary>
    /// Deserializes the data into a concrete type
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public PdsLocation[] Extract() {
        var sequence = Value.OfType<DerAsnSequence>().FirstOrDefault();
        if (sequence == null)
            return null;

        var list = new List<PdsLocation>();
        foreach (var item in sequence.Value.OfType<DerAsnSequence>()) {
            list.Add(new PdsLocation {
                Url = ((DerAsnIa5String)item.Value[0]).Value,
                Language = ((DerAsnPrintableString)item.Value[1]).Value,
            });
        }
        return list.ToArray();
    }

}


/// <summary>
/// <b>QcType</b>. claiming that the certificate is a certificate of a particular type
/// </summary>
/// <remarks>
/// esi4-qcStatement-6 QC-STATEMENT ::= { SYNTAX QcType IDENTIFIED BY id-etsi-qcs-QcType }
/// 
/// id-etsi-qcs-QcType OBJECT IDENTIFIER ::= { id-etsi-qcs 6 }
///     QcType::= SEQUENCE OF OBJECT IDENTIFIER (id-etsi-qct-esign | id-etsi-qct-eseal | id-etsi-qct-web, ...)
/// 
/// -- QC type identifiers
/// id-etsi-qct-esign OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 1 }
/// -- Certificate for electronic signatures as defined in Regulation (EU) No 910/2014
/// id-etsi-qct-eseal OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 2 }
/// -- Certificate for electronic seals as defined in Regulation (EU) No 910/2014
/// id-etsi-qct-web OBJECT IDENTIFIER ::= { id-etsi-qcs-QcType 3 }
/// -- Certificate for website authentication as defined in Regulation (EU) No 910/2014 
/// </remarks>
public class QcTypeStatement : DerAsnSequence
{

    /// <summary>
    /// id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::=  {itu-t(0) identified-organization(4) etsi(0) qc-profile(1862) qcs(1) qcs-QcType(6)}
    /// </summary>
    public const string Oid_QcType = "0.4.0.1862.1.6";

    /// <summary>
    /// Constructs the QcStatement so it can be added to a certificate.
    /// </summary>
    public QcTypeStatement(QcTypeIdentifiers type) : base(Array.Empty<DerAsnType>()) {
        var oid = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_QcType.OidToArray());
        var oidType = new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, (Oid_QcType + "." + (int)type).OidToArray());
        Value = new DerAsnType[] { oid, new DerAsnSequence(new DerAsnType[] { oidType }) };
    }

    /// <summary>
    /// constructs the QcStatement from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public QcTypeStatement(DerAsnType[] value) : base(value) {

    }


    /// <summary>
    /// Deserializes the data into a concrete type
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public QcTypeIdentifiers Extract() {
        var sequence = Value.OfType<DerAsnSequence>().FirstOrDefault();
        var oid = (DerAsnObjectIdentifier)sequence.Value[0];
        return (QcTypeIdentifiers)oid.Value.Last();
    }

}

/// <summary>
///  QC type identifiers
/// </summary>
public enum QcTypeIdentifiers
{
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
    public string Url { get; set; }
    /// <summary>
    /// ISO 639-1 language code
    /// </summary>
    public string Language { get; set; }
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
    public string CurrencyCode { get; set; }
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
    public QualifiedCertificateStatements(bool isCompliant, QcMonetaryValue limit, int retentionPeriod, bool isQSCD, IEnumerable<PdsLocation> pdsLocations, QcTypeIdentifiers type, Psd2Attributes psd2) {
        IsCompliant = isCompliant;
        LimitValue = limit;
        RetentionPeriod = retentionPeriod;
        IsQSCD = isQSCD;
        PdsLocations = pdsLocations.ToArray();
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
    public QcMonetaryValue LimitValue { get; internal set; }
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
    public PdsLocation[] PdsLocations { get; internal set; }

    /// <summary>
    /// <b>QcType</b>. claiming that the certificate is a certificate of a particular type
    /// </summary>
    public QcTypeIdentifiers Type { get; internal set; }

    /// <summary>
    /// <b>Psd2QcType</b>. Attributes specific to the PSD2 directive.
    /// </summary>
    public Psd2Attributes Psd2Type { get; internal set; }
}

