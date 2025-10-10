using System.Collections.Generic;
using System.Linq;
using System.Text;
using DerConverter.Asn;

namespace Indice.Cryptography.X509Certificates.DerAsnTypes;

internal class ContextSpecificString : DerAsnType<string>
{
    public static readonly DerAsnIdentifier Id = new DerAsnIdentifier(DerAsnTagClass.ContextSpecific, DerAsnEncodingType.Primitive, DerAsnKnownTypeTags.Primitive.ObjectIdentifier);

    internal ContextSpecificString(IDerAsnDecoder decoder, DerAsnIdentifier identifier, Queue<byte> rawData)
        : base(decoder, identifier, rawData) {
    }

    public ContextSpecificString(string value)
        : base(Id, value) {
    }

    protected override string DecodeValue(IDerAsnDecoder decoder, Queue<byte> rawData) {
        return Encoding.ASCII.GetString(rawData.DequeueAll().ToArray());
    }

    protected override IEnumerable<byte> EncodeValue(IDerAsnEncoder encoder, string value) {
        return Encoding.ASCII.GetBytes(value);
    }
}
