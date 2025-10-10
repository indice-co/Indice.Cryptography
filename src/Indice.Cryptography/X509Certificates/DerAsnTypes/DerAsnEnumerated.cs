using System.Collections.Generic;
using DerConverter.Asn;

namespace Indice.Cryptography.X509Certificates.DerAsnTypes;

internal class DerAsnEnumerated : DerAsnType<byte>
{
    public static readonly DerAsnIdentifier Id = new DerAsnIdentifier(DerAsnTagClass.Universal, DerAsnEncodingType.Primitive, DerAsnKnownTypeTags.Primitive.Enumerated);

    internal DerAsnEnumerated(IDerAsnDecoder decoder, DerAsnIdentifier identifier, Queue<byte> rawData)
        : base(decoder, identifier, rawData) {
    }

    public DerAsnEnumerated(byte value)
        : base(Id, value) {
    }

    protected override byte DecodeValue(IDerAsnDecoder decoder, Queue<byte> rawData) {
        return rawData.Dequeue();
    }

    protected override IEnumerable<byte> EncodeValue(IDerAsnEncoder encoder, byte value) {
        return new[] { value };
    }
}
