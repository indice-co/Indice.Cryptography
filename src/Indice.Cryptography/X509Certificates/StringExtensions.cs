using System;
using System.Collections.Generic;
using System.Linq;

namespace Indice.Cryptography.X509Certificates;

internal static class StringExtensions
{
    public static int[] OidToArray(this string oid) {
        return oid.Split('.').Select(x => int.Parse(x)).ToArray();
    }
    public static string ToOidString(this int[] oid) {
        return string.Join('.', oid);
    }

    public static string ToHexString(this IEnumerable<byte> data) {
        var text = string.Join("", data.Select(x => x.ToString("X2")));
        return text;
    }
    public static byte[] HexToBytes(this string hex) {
        if (hex.Length % 2 == 1)
            throw new Exception("The binary key cannot have an odd number of digits");

        byte[] arr = new byte[hex.Length >> 1];

        for (int i = 0; i < hex.Length >> 1; ++i) {
            arr[i] = (byte)((GetHexVal(hex[i << 1]) << 4) + (GetHexVal(hex[(i << 1) + 1])));
        }

        return arr;
    }

    private static int GetHexVal(char hex) {
        int val = (int)hex;
        //For uppercase A-F letters:
        return val - (val < 58 ? 48 : 55);
        //For lowercase a-f letters:
        //return val - (val < 58 ? 48 : 87);
        //Or the two combined, but a bit slower:
        //return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
    }
}
