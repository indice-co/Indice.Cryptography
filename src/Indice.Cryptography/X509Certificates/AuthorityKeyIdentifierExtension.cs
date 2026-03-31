using System;
using System.Formats.Asn1;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// The AuthorityKeyIdentifier extension. There is no built-in 
/// support, so it needs to be copied from the Subject Key 
/// Identifier of the signing certificate and massaged slightly.
/// AuthorityKeyIdentifier is "KeyID="
/// </summary>
public class AuthorityKeyIdentifierExtension : X509Extension
{
    /// <summary>
    /// Authority Key Identifier Oid (X509 v3)
    /// </summary>
    public const string Oid_AuthorityKeyIdentifier = "2.5.29.35";

    /// <summary>
    /// Subject Key Identifier Oid (X509 v3)
    /// </summary>
    public const string Oid_SubjectKeyIdentifier = "2.5.29.14";

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="issuerKeyIdentifier">The subject key identifier of the issuer certificate in Hex string</param>
    /// <param name="critical"></param>
    public AuthorityKeyIdentifierExtension(string issuerKeyIdentifier, bool critical) {
        Oid = new Oid(Oid_AuthorityKeyIdentifier, "Authority Key Identifier");
        Critical = critical;

        byte[] keyBytes = HexStringToByteArray(issuerKeyIdentifier);
        RawData = EncodeAuthorityKeyIdentifier(keyBytes);

        _KeyId = issuerKeyIdentifier;
        _decoded = true;
    }

    /// <summary>
    /// Used to create the extension from typed model
    /// </summary>
    /// <param name="issuerKeyIdentifier">The subject key identifier of the issuer certificate</param>
    /// <param name="critical"></param>
    public AuthorityKeyIdentifierExtension(byte[] issuerKeyIdentifier, bool critical) {
        Oid = new Oid(Oid_AuthorityKeyIdentifier, "Authority Key Identifier");
        Critical = critical;
        RawData = EncodeAuthorityKeyIdentifier(issuerKeyIdentifier);
        _decoded = false;
    }

    /// <summary>
    /// Used to deserialize from an existing extension instance.
    /// </summary>
    /// <param name="encodedExtension"></param>
    /// <param name="critical"></param>
    public AuthorityKeyIdentifierExtension(AsnEncodedData encodedExtension, bool critical)
        : base(encodedExtension, critical) {
    }

    private bool _decoded = false;
    private string? _KeyId;

    /// <summary>
    /// The deserialized contents
    /// </summary>
    public string? AuthorityKeyIdentifier {
        get {
            if (!_decoded) {
                DecodeExtension();
            }
            return _KeyId;
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

    /// <summary>
    /// Encode authority key identifier using System.Formats.Asn1
    /// </summary>
    private static byte[] EncodeAuthorityKeyIdentifier(byte[] keyBytes) {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.PushSequence();
        {
            // Context-specific [0] IMPLICIT OCTET STRING
            writer.WriteOctetString(keyBytes, new Asn1Tag(TagClass.ContextSpecific, 0));
        }
        writer.PopSequence();

        return writer.Encode();
    }

    private void DecodeExtension() {
        try {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            var seqReader = reader.ReadSequence();

            // Read context-specific [0] IMPLICIT OCTET STRING
            var tag = seqReader.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && (int)tag.TagValue == 0) {
                // Read the octet string with context-specific tag
                var keyBytes = seqReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                _KeyId = string.Join("", keyBytes.ToArray().Select(x => x.ToString("X2")));
            }
        } catch (Exception ex) {
            throw new InvalidOperationException("Failed to decode AuthorityKeyIdentifier extension.", ex);
        }

        _decoded = true;
    }

    private static byte[] HexStringToByteArray(string hex) {
        if (hex.Length % 2 == 1)
            throw new ArgumentException("The binary key cannot have an odd number of digits", nameof(hex));

        byte[] arr = new byte[hex.Length >> 1];
        for (int i = 0; i < hex.Length >> 1; ++i) {
            arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
        }
        return arr;
    }

    private static int GetHexVal(char hex) {
        int val = (int)hex;
        return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
    }
}
