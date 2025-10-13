using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using DerConverter.Asn;
using DerConverter.Asn.KnownTypes;
using Indice.Cryptography.X509Certificates.DerAsnTypes;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Certificate revocation list CRL
/// </summary>
public class CertificateRevocationListSequence : DerAsnSequence
{
    /// <summary>
    /// Oid for CRL reason
    /// </summary>
    public const string Oid_CRL_Reason = "2.5.29.21";
    /// <summary>
    /// Oid for the signing algorythm.
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
    /// Oid for issuer Subject O.
    /// </summary>
    public const string Oid_AuthorityKey = "2.5.29.35";
    /// <summary>
    /// Oid for issuer Subject O.
    /// </summary>
    public const string Oid_CRLNumber = "2.5.29.20";
    /// <summary>
    /// Constructs the <see cref="CertificateRevocationListSequence"/> from <see cref="RevokedCertificate"/>.
    /// </summary>
    /// <param name="crl">The data use in order to load the sequence</param>
    public CertificateRevocationListSequence(CertificateRevocationList crl) : base(new DerAsnType[0]) {
        //var container = new List<DerAsnType>();
        var details = new List<DerAsnType>();
        var list = new List<DerAsnSequence>();
        foreach (var cert in crl.Items) {
            var definition = new List<DerAsnType>();
            var serialNumber = new DerAsnInteger(BigInteger.Parse(cert.SerialNumber!.ToUpper(), NumberStyles.AllowHexSpecifier));
            var revocationDate = new DerAsnUtcTime(cert.RevocationDate);
            var reason = new DerAsnSequence(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType [] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_CRL_Reason.OidToArray()),
                    new OctetStringSequence(new [] { new DerAsnEnumerated((byte)cert.ReasonCode) })
                })
            });
            definition.Add(serialNumber);
            definition.Add(revocationDate);
            definition.Add(reason);
            list.Add(new DerAsnSequence(definition.ToArray()));
        }
        details.Add(new DerAsnInteger(new BigInteger(1)));
        details.Add(new DerAsnSequence(new DerAsnType[] {
            new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_sha256RSA.OidToArray()),
            new DerAsnNull()
        }));
        details.Add(new DerAsnSequence(new DerAsnType[] {
            new DerAsnSet(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType[] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_Issuer_C.OidToArray()),
                    new DerAsnPrintableString(crl.Country)
                })
            }),
            new DerAsnSet(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType[] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_Issuer_O.OidToArray()),
                    new DerAsnPrintableString(crl.Organization)
                })
            }),
            new DerAsnSet(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType[] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_Issuer_CN.OidToArray()),
                    new DerAsnPrintableString(crl.IssuerCommonName)
                })
            })
        }));
        details.Add(new DerAsnUtcTime(crl.EffectiveDate));
        details.Add(new DerAsnUtcTime(crl.NextUpdate));
        details.Add(new DerAsnSequence(list.ToArray()));
        details.Add(new ContextSpecificSequence(new DerAsnType[] {
            new DerAsnSequence(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType[] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_AuthorityKey.OidToArray()),
                    new OctetStringSequence(new DerAsnType[] {
                        new DerAsnSequence(new DerAsnType[] {
                            new DerAsnOctetString(new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Primitive, 0x0), crl.AuthorizationKeyId.HexToBytes())
                        })
                    })
                })
            }),
            new DerAsnSequence(new DerAsnType[] {
                new DerAsnSequence(new DerAsnType[] {
                    new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_CRLNumber.OidToArray()),
                     new OctetStringSequence(new DerAsnType[] {
                       new DerAsnInteger(new BigInteger(crl.CrlNumber))
                    })
                })
            })
        }));
        Value = details.ToArray();
        //container.Add(new DerAsnSequence(details.ToArray()));
        //Value = container.ToArray();
    }

    /// <summary>
    /// Creates the CRL envelope and includes the RSA signature with it.
    /// </summary>
    /// <param name="signingKey"></param>
    /// <param name="encoder"></param>
    /// <returns></returns>
    public byte[] SignAndSerialize(RSA signingKey, IDerAsnEncoder? encoder = null) {
        var data = DerConverter.DerConvert.Encode(this);
        var signature = signingKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var container = new DerAsnSequence(new DerAsnType[] {
            this,
            new DerAsnSequence(new DerAsnType[] {
                new DerAsnObjectIdentifier(DerAsnIdentifiers.Primitive.ObjectIdentifier, Oid_sha256RSA.OidToArray()),
                new DerAsnNull()
            }),
            new DerAsnBitString(new BitArray(signature))
        });
        return DerConverter.DerConvert.Encode(container);
    }

    /// <summary>
    /// constructs the <see cref="CertificateRevocationListSequence"/> from an array of ANS.1 Der encoded data.
    /// </summary>
    /// <param name="value"></param>
    public CertificateRevocationListSequence(DerAsnType[] value) : base(value) {

    }

    /// <summary>
    /// Deserializes the raw data into the list.
    /// </summary>
    /// <returns>Deserilized contents</returns>
    public CertificateRevocationList Extract() {
        var crl = new CertificateRevocationList();
        var details = Value[0] as DerAsnSequence;
        var version = details!.Value[0] as DerAsnInteger;
        var algorithm = ((DerAsnSequence)details.Value[1]).Value[0] as DerAsnObjectIdentifier;
        var subject = ((DerAsnSequence)details.Value[2]).Value.Cast<DerAsnSet>();
        crl.EffectiveDate = ((DerAsnUtcTime)details.Value[3]).Value.DateTime;
        crl.NextUpdate = ((DerAsnUtcTime)details.Value[4]).Value.DateTime;

        IEnumerable<DerAsnSequence> list = [];
        DerAsnType[] info = [];
        if (details.Value.Length == 7) {
            list = ((DerAsnSequence)details.Value[5]).Value.Cast<DerAsnSequence>();
            info = ((DerAsnSequence)((ContextSpecificSequence)details.Value[6]).Value[0]).Value;
        } else if (details.Value.Length == 6) {
            info = ((DerAsnSequence)((ContextSpecificSequence)details.Value[5]).Value[0]).Value;
        }
        foreach (var part in subject) {
            var seq = ((DerAsnSequence)part.Value[0]);
            var oid = seq.Value[0] as DerAsnObjectIdentifier;
            var text = seq.Value[1] as DerAsnPrintableString;
            var oidString = string.Join(".", oid!.Value);
            switch (oidString) {
                case Oid_Issuer_C: crl.Country = text!.Value; break;
                case Oid_Issuer_O: crl.Organization = text!.Value; break;
                case Oid_Issuer_CN: crl.IssuerCommonName = text!.Value; break;
            }
        }
        foreach (var item in list) {
            var serialNumber = item.Value[0] as DerAsnInteger;
            var revocationDate = item.Value[1] as DerAsnUtcTime;
            var reason = default(RevokedCertificate.CRLReasonCode);
            if (item.Value.Length > 2) {
                var reasonData = ((DerAsnSequence)((DerAsnSequence)item.Value[2]).Value[0]).Value[1];
                if (reasonData is OctetStringSequence) {
                    var reasonSeq = reasonData as OctetStringSequence;
                    reason = (RevokedCertificate.CRLReasonCode)((DerAsnEnumerated)reasonSeq!.Value[0]).Value;
                } else if (reasonData is DerAsnOctetString) {
                    reason = (RevokedCertificate.CRLReasonCode)((DerAsnOctetString)reasonData).Value[2];
                }
            }
            crl.Items.Add(new RevokedCertificate {
                RevocationDate = revocationDate!.Value.DateTime,
                SerialNumber = serialNumber!.Value.ToString("x16"),
                ReasonCode = reason
            });
        }
        foreach (DerAsnSequence item in info) {
            var oid = item.Value[0] as DerAsnObjectIdentifier;
            var oidString = string.Join(".", oid!.Value);
            var data = item.Value[1] as DerAsnOctetString;
            switch (oidString) {
                case Oid_AuthorityKey: crl.AuthorizationKeyId = string.Join("", data!.Value.Skip(4).Select(x => x.ToString("X2"))); break;
                case Oid_CRLNumber: crl.CrlNumber = (int)new BigInteger(data!.Value.Skip(3).ToArray()); break;
            }
        }
        return crl;
    }

    /// <summary>
    /// Create a CRL from raw DER ASN.1 data
    /// </summary>
    /// <returns></returns>
    public static CertificateRevocationListSequence Load(byte[] rawData) {
        if (rawData == null) {
            throw new ArgumentNullException(nameof(rawData));
        }

        CertificateRevocationListSequence sequence;
        using (var decoder = new DefaultDerAsnDecoder()) {
            decoder.RegisterType(ContextSpecificSequence.Id, (dcdr, identifier, data) => new ContextSpecificSequence(dcdr, identifier, data));
            decoder.RegisterType(OctetStringSequence.Id, (dcdr, identifier, data) => new OctetStringSequence(dcdr, identifier, data));
            decoder.RegisterType(DerAsnEnumerated.Id, (dcdr, identifier, data) => new DerAsnEnumerated(dcdr, identifier, data));
            sequence = new CertificateRevocationListSequence(((DerAsnSequence)decoder.Decode(rawData)).Value);
        }
        return sequence;
    }

}

/// <summary>
/// Dto that represents a revocation list
/// </summary>
public class CertificateRevocationList
{
    /// <summary>
    /// Issueer CN
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
    /// Looks like the id of the list.
    /// </summary>
    public int CrlNumber { get; set; }
    /// <summary>
    /// Date when the list will become effective.
    /// </summary>
    public DateTime EffectiveDate { get; set; }
    /// <summary>
    /// When the list should be looked upon again
    /// </summary>
    public DateTime NextUpdate { get; set; }
    /// <summary>
    /// The Subject key Identitfier of the issuing certificate.
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
    /// Certificate serialnumber.
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
        /// Replaced by a new certificate
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
    /// <returns></returns>
    public override string ToString() => $"{SerialNumber} {RevocationDate}";
}
