using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// Http Instance digest. Used in a <see cref="HttpSignatureSecurityToken"/> https://tools.ietf.org/html/rfc3230
/// </summary>
public sealed class HttpDigest
{
    /// <summary>
    /// The header name for this part.
    /// </summary>
    public const string HTTPHeaderName = "Digest";

    /// <summary>
    /// provides a mapping for the 'algorithm' value so that values are within the Http Signature namespace.
    /// </summary>
    private static readonly IDictionary<string, string> OutboundAlgorithmMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        [HashAlgorithmName.MD5.Name!] = "md5",
        [HashAlgorithmName.SHA1.Name!] = "sha-1",
        [HashAlgorithmName.SHA256.Name!] = "sha-256",
        [HashAlgorithmName.SHA384.Name!] = "sha-384",
        [HashAlgorithmName.SHA512.Name!] = "sha-512",
        [SecurityAlgorithms.RsaSha256] = "sha-256",
        [SecurityAlgorithms.RsaSha256Signature] = "sha-256",
        [SecurityAlgorithms.RsaSha384] = "sha-384",
        [SecurityAlgorithms.RsaSha384Signature] = "sha-384",
        [SecurityAlgorithms.RsaSha512] = "sha-512",
        [SecurityAlgorithms.RsaSha512Signature] = "sha-512",
        [SecurityAlgorithms.HmacSha256Signature] = "sha-256",
        [SecurityAlgorithms.HmacSha256] = "sha-256",
        [SecurityAlgorithms.HmacSha384Signature] = "sha-384",
        [SecurityAlgorithms.HmacSha384] = "sha-384",
        [SecurityAlgorithms.HmacSha512Signature] = "sha-512",
        [SecurityAlgorithms.HmacSha512] = "sha-512"
    };

    /// <summary>
    /// provides a mapping for the 'algorithm' value so that values are within the Http Signature namespace.
    /// </summary>
    private static readonly IDictionary<string, HashAlgorithmName> InboundAlgorithmMap = new Dictionary<string, HashAlgorithmName>(StringComparer.OrdinalIgnoreCase) {
        ["md5"] = HashAlgorithmName.MD5,
        ["sha-1"] = HashAlgorithmName.SHA1,
        ["sha-256"] = HashAlgorithmName.SHA256,
        ["sha-384"] = HashAlgorithmName.SHA384,
        ["sha-512"] = HashAlgorithmName.SHA512,
    };

    /// <summary>
    /// construct the http digest
    /// </summary>
    public HttpDigest() : this(nameof(HashAlgorithmName.SHA256), Encoding.UTF8.GetBytes(string.Empty)) {
    }

    /// <summary>
    /// construct the http digest
    /// </summary>
    /// <param name="algorithm"></param>
    /// <param name="requestBody"></param>
    public HttpDigest(string algorithm, byte[] requestBody) {
        if (OutboundAlgorithmMap.TryGetValue(algorithm, out string? outboundAlg))
            Algorithm = outboundAlg;
        else
            Algorithm = algorithm;
        Output = HashToBase64(InboundAlgorithmMap[Algorithm], requestBody);
    }

    /// <summary>
    /// Digest algorithm values are used to indicate a specific digest
    /// computation.For some algorithms, one or more parameters may be
    /// supplied. (ie. sha-256, sha-512, SHA, MD5, UNIXsum, UNIXcksum)
    /// </summary>
    public string Algorithm { get; set; }

    /// The encoded digest output uses the encoding format defined for the
    /// specific digest-algorithm.For example, if the digest-algorithm is
    /// "MD5", the encoding is base64; if the digest-algorithm is "UNIXsum",
    /// the encoding is an ASCII string of decimal digits.
    public string Output { get; set; }

    /// <summary>
    /// Serializes this instance to string.
    /// </summary>
    /// <returns>This instance as an http header value.</returns>
    public override string ToString() {
        return $"{Algorithm}={Output}";
    }

    /// <summary>
    /// validates digest
    /// </summary>
    /// <returns></returns>
    public bool Validate(byte[] requestBody) {
        if (!InboundAlgorithmMap.ContainsKey(Algorithm)) {
            throw new Exception($"Cannot validate Digest. Unsupported hashing algorithm '{Algorithm}'");
        }
        var hash = HashToBase64(InboundAlgorithmMap[Algorithm], requestBody);
        return hash.Equals(Output);
    }

    private static string HashToBase64(HashAlgorithmName algorithm, byte[] requestBody) {
        var hash = default(byte[]);
        using (var hashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(algorithm.Name!)!) {
            hash = hashAlgorithm.ComputeHash(requestBody);
        }
        return Convert.ToBase64String(hash);
    }

    /// <summary>
    /// Parses the header value string into an <see cref="HttpDigest"/> instance.
    /// </summary>
    /// <param name="headerValue"></param>
    /// <returns></returns>
    public static HttpDigest Parse(string headerValue) {
        var equalsSignPosition = headerValue.IndexOf('='); // do not use split because base64 uses the equals sign.
        if (equalsSignPosition < 0) {
            throw new FormatException($"Cannot parse HttpDigest from raw value {headerValue}");
        }
        var digest = new HttpDigest {
            Algorithm = headerValue.Substring(0, equalsSignPosition),
            Output = headerValue.Substring(equalsSignPosition + 1),
        };
        return digest;
    }
}
