using System.Formats.Asn1;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Extension methods and helpers for ASN.1 encoding/decoding using System.Formats.Asn1
/// </summary>
internal static class Asn1ExtensionsHelper
{
    /// <summary>
    /// Converts an OID string (e.g., "2.5.4.3") to byte array for OID encoding
    /// </summary>
    public static void WriteObjectIdentifierFromString(this AsnWriter writer, string oidString)
    {
        writer.WriteObjectIdentifier(oidString);
    }

    /// <summary>
    /// Helper to read context-specific [N] tagged value
    /// </summary>
    public static AsnReader ReadContextSpecificSequence(this AsnReader reader, int tagNumber)
    {
        return reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber));
    }

    /// <summary>
    /// Helper to read optional context-specific [N] tagged value
    /// </summary>
    public static AsnReader? TryReadContextSpecificSequence(this AsnReader reader, int tagNumber)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass == TagClass.ContextSpecific && (int)tag.TagValue == tagNumber)
        {
            return reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber));
        }
        return null;
    }

    /// <summary>
    /// Helper to write context-specific [N] tagged octet string
    /// </summary>
    public static void WriteContextSpecificOctetString(this AsnWriter writer, int tagNumber, byte[] data)
    {
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber));
        writer.WriteOctetString(data);
        writer.PopSequence();
    }

    /// <summary>
    /// Helper to write context-specific [N] tagged sequence
    /// </summary>
    public static void PushContextSpecificSequence(this AsnWriter writer, int tagNumber)
    {
        writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, tagNumber));
    }
}
