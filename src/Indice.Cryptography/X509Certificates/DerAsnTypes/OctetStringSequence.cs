using System.Collections.Generic;
using System.Linq;
using DerConverter.Asn;

namespace Indice.Cryptography.X509Certificates.DerAsnTypes;

internal class OctetStringSequence : DerAsnType<DerAsnType[]>
{
    public static readonly DerAsnIdentifier Id = new DerAsnIdentifier(DerAsnTagClass.Universal, DerAsnEncodingType.Constructed, 0x4);

    public OctetStringSequence(IDerAsnDecoder decoder, DerAsnIdentifier identifier, Queue<byte> rawData)
        : base(decoder, identifier, rawData) {
    }

    public OctetStringSequence(DerAsnType[] value)
        : base(Id, value) {
    }

    protected override DerAsnType[] DecodeValue(IDerAsnDecoder decoder, Queue<byte> rawData) {
        var items = new List<DerAsnType>();
        while (rawData.Any()) items.Add(decoder.Decode(rawData));
        return items.ToArray();
    }

    protected override IEnumerable<byte> EncodeValue(IDerAsnEncoder encoder, DerAsnType[] value) {
        return value
            .Select(x => encoder.Encode(x))
            .SelectMany(x => x)
            .ToArray();
    }
}
