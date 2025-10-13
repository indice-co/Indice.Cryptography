using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// The Signature HTTP Header, which is typically used by automated software agents.
/// As described in https://tools.ietf.org/html/draft-cavage-http-signatures-10
/// </summary>
public class HttpSignature : Dictionary<string, object?>
{
    /// <summary>
    /// The header name for this part.
    /// </summary>
    public const string HTTPHeaderName = "Signature";

    /// <summary>
    /// Provides a mapping for the 'algorithm' value so that values are within the HTTP Signature namespace.
    /// </summary>
    private readonly IDictionary<string, string> OutboundAlgorithmMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        [SecurityAlgorithms.RsaSha256Signature] = "rsa-sha256",
        [SecurityAlgorithms.RsaSha512Signature] = "rsa-sha512",
        [SecurityAlgorithms.RsaSha256] = "rsa-sha256",
        [SecurityAlgorithms.RsaSha384] = "rsa-sha384",
        [SecurityAlgorithms.RsaSha512] = "rsa-sha512",
        [SecurityAlgorithms.HmacSha256Signature] = "hmac-sha256",
        [SecurityAlgorithms.HmacSha256] = "hmac-sha256",
        [SecurityAlgorithms.HmacSha384Signature] = "hmac-sha384",
        [SecurityAlgorithms.HmacSha384] = "hmac-sha384",
        [SecurityAlgorithms.HmacSha512Signature] = "hmac-sha512",
        [SecurityAlgorithms.HmacSha512] = "hmac-sha512"
    };

    /// <summary>
    /// Provides a mapping for the 'algorithm' value so that values are within the HTTP Signature namespace.
    /// </summary>
    private readonly IDictionary<string, string> InboundAlgorithmMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
        ["rsa-sha256"] = SecurityAlgorithms.RsaSha256Signature,
        ["rsa-sha384"] = SecurityAlgorithms.RsaSha384Signature,
        ["rsa-sha512"] = SecurityAlgorithms.RsaSha512Signature,
        ["hmac-sha256"] = SecurityAlgorithms.HmacSha256Signature,
        ["hmac-sha384"] = SecurityAlgorithms.HmacSha384Signature,
        ["hmac-sha512"] = SecurityAlgorithms.HmacSha512Signature
    };

    /// <summary>
    /// Initializes a new instance of <see cref="HttpSignature"/>.
    /// </summary>
    public HttpSignature() : this(null, null) { }

    /// <summary>
    /// Initializes a new instance of <see cref="HttpSignature"/>.
    /// </summary>
    /// <param name="signingCredentials"><see cref="SigningCredentials"/> used when creating the signature header.</param>
    /// <param name="headerKeyValuesToSign">The signing string contains several headers depending on which API you are using. The order is not important as long as you define them in the same order in the signature header.</param>
    /// <param name="createdDate">Date to use on the created component. Useful if the requestDate is missing from the HTTP headers.</param>
    /// <param name="expirationDate">Expiration date.</param>
    public HttpSignature(SigningCredentials? signingCredentials, IDictionary<string, string?>? headerKeyValuesToSign, DateTime? createdDate = null, DateTime? expirationDate = null) : base(StringComparer.OrdinalIgnoreCase) {
        if (signingCredentials == null) {
            this[HttpSignatureParameterNames.Algorithm] = SecurityAlgorithms.None;
        } else {
            if (OutboundAlgorithmMap.TryGetValue(signingCredentials.Algorithm, out string? outboundAlg)) {
                Algorithm = outboundAlg;
            } else {
                Algorithm = signingCredentials.Algorithm;
            }
            if (!string.IsNullOrEmpty(signingCredentials.Key.KeyId)) {
                KeyId = signingCredentials.Key.KeyId;
            }
            headerKeyValuesToSign ??= new Dictionary<string, string?>();
            var message = GenerateMessage(headerKeyValuesToSign);
            var hashingAlgorithm = signingCredentials.Algorithm == OutboundAlgorithmMap[SecurityAlgorithms.RsaSha512Signature] ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256;
            if (signingCredentials is X509SigningCredentials x509SigningCredentials) {
                using (var key = x509SigningCredentials.Certificate.GetRSAPrivateKey()!) {
                    this[HttpSignatureParameterNames.Signature] = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(message), hashingAlgorithm, RSASignaturePadding.Pkcs1));
                }
            } else if (signingCredentials.Key is RsaSecurityKey rsaKey) {
                this[HttpSignatureParameterNames.Signature] = Convert.ToBase64String(HashAndSignBytes(Encoding.UTF8.GetBytes(message), rsaKey.Parameters, hashingAlgorithm)!);
            } else if (signingCredentials.Key is X509SecurityKey x509Key) {
                this[HttpSignatureParameterNames.Signature] = Convert.ToBase64String(HashAndSignBytes(Encoding.UTF8.GetBytes(message), (RSACng)x509Key.PrivateKey, hashingAlgorithm)!);
            }
            Headers = new HashSet<string>(headerKeyValuesToSign.Where(x => x.Value != null).Select(x => x.Key.ToLowerInvariant()));
            if (headerKeyValuesToSign.TryGetValue(HeaderFieldNames.Created, out var value)) {
                Created = GetDate(value);
            }
            if (createdDate.HasValue) {
                Created = createdDate.Value;
            }
            if (expirationDate.HasValue) {
                Expires = expirationDate.Value;
            }
        }
        SigningCredentials = signingCredentials;
    }

    private static byte[]? HashAndSignBytes(byte[] DataToSign, RSACng RSAalg, HashAlgorithmName hashAlgorithm) {
        // Create a new instance of RSACryptoServiceProvider using the key from RSAParameters.  
        try {
            // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider to specify the use of SHA1 for hashing.
            return RSAalg.SignData(DataToSign, hashAlgorithm, RSASignaturePadding.Pkcs1);
        } catch (CryptographicException e) {
            Console.WriteLine(e.Message);
            return null;
        }
    }

    private static byte[]? HashAndSignBytes(byte[] DataToSign, RSAParameters Key, HashAlgorithmName hashAlgorithm) {
        // Create a new instance of RSACryptoServiceProvider using the key from RSAParameters.  
        using (var RSAalg = new RSACryptoServiceProvider()) {
            try {
                RSAalg.ImportParameters(Key);
                // Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider to specify the use of SHA1 for hashing.
                return RSAalg.SignData(DataToSign, hashAlgorithm, RSASignaturePadding.Pkcs1);
            } catch (CryptographicException e) {
                Console.WriteLine(e.Message);
                return null;
            } finally {
                // Set the key container to be cleared when RSA is garbage collected.
                RSAalg.PersistKeyInCsp = false;
            }
        }
    }

    /// <summary>
    /// REQUIRED.The `keyId` field is an opaque string that the server can
    /// use to look up the component they need to validate the signature.It
    /// could be an SSH key fingerprint, a URL to machine-readable key data,
    /// an LDAP DN, etc.
    /// </summary>
    public string? KeyId {
        get => GetSafeComponent(HttpSignatureParameterNames.KeyId);
        set => this[HttpSignatureParameterNames.KeyId] = value;
    }

    /// <summary>
    /// REQUIRED.  The `signature` parameter is a base 64 encoded digital signature.
    /// The client uses the `algorithm` and `headers` signature parameters to
    /// form a canonicalized `signing string`.  This `signing string` is then
    /// signed with the key associated with `keyId` and the algorithm
    /// corresponding to `algorithm`.  The `signature` parameter is then set
    /// to the base 64 encoding of the signature.
    /// </summary>
    public string? Signature {
        get => GetSafeComponent(HttpSignatureParameterNames.Signature);
        set => this[HttpSignatureParameterNames.Signature] = value;
    }

    /// <summary>
    /// OPTIONAL.The `headers` parameter is used to specify the list of
    /// HTTP headers included when generating the signature for the message.
    /// If specified, it should be a lowercased, quoted list of HTTP header
    /// fields, separated by a single space character.  If not specified,
    /// implementations MUST operate as if the field were specified with a
    /// single value, the `Date` header, in the list of HTTP headers.Note
    /// that the list order is important, and MUST be specified in the order
    /// the HTTP header field-value pairs are concatenated together during
    /// signing.
    /// </summary>
    public HashSet<string> Headers {
        get => new HashSet<string>(GetSafeComponent(HttpSignatureParameterNames.Headers)?.Split(' ', StringSplitOptions.RemoveEmptyEntries) ?? [], StringComparer.OrdinalIgnoreCase);
        set => this[HttpSignatureParameterNames.Headers] = string.Join(" ", (value ?? []));
    }

    /// <summary>
    /// RECOMMENDED.  The `created` field expresses when the signature was
    /// created.  The value MUST be a Unix timestamp integer value.  A
    /// signature with a `created` timestamp value that is in the future MUST
    /// NOT be processed.  Using a Unix timestamp simplifies processing and
    /// avoids timezone management required by specifications such as
    /// RFC3339.  Subsecond precision is not supported.  This value is useful
    /// when clients are not capable of controlling the `Date` HTTP Header
    /// such as when operating in certain web browser environments.
    /// </summary>
    public DateTime? Created {
        get => GetSafeDate(HttpSignatureParameterNames.Created);
        set => this[HttpSignatureParameterNames.Created] = value;
    }

    /// <summary>
    /// OPTIONAL.  The `expires` field expresses when the signature ceases to
    /// be valid.  The value MUST be a Unix timestamp integer value.  A
    /// signatures with a `expires` timestamp value that is in the past MUST
    /// NOT be processed.  Using a Unix timestamp simplifies processing and
    /// avoid timezone management existing in RFC3339.  Subsecod precision is
    /// allowed using decimal notation.
    /// </summary>
    public DateTime? Expires {
        get => GetSafeDate(HttpSignatureParameterNames.Expires);
        set => this[HttpSignatureParameterNames.Expires] = value;
    }

    /// <summary>
    /// OPTIONAL.  The `algorithm` parameter is used to specify the digital
    /// signature algorithm to use when generating the signature.  Valid
    /// values for this parameter can be found in the Signature Algorithms
    /// registry located at http://www.iana.org/assignments/signature-algorithms [6]
    /// and MUST NOT be marked "deprecated".  It is preferred
    /// that the algorithm used by an implementation be derived from the key
    /// metadata identified by the `keyId` rather than from this field.  If
    /// `algorithm` is provided and differs from the key metadata identified
    /// by the `keyId` then an implementation MUST produce an error.  The
    /// `algorithm` parameter, which may be specified by an attacker, has the
    /// potential to create security vulnerabilities and will most likely be
    /// deprecated in the future.
    /// </summary>
    public string? Algorithm {
        get => GetSafeComponent(HttpSignatureParameterNames.Algorithm);
        set => this[HttpSignatureParameterNames.Algorithm] = value;
    }

    /// <summary>
    /// Gets the <see cref="SigningCredentials"/> passed in the constructor.
    /// </summary>
    /// <remarks>This value may be null.</remarks>
    public SigningCredentials? SigningCredentials { get; }

    /// <summary>
    /// Gets a component from the header value.
    /// A component is either a string or a value of another type serialized in http header value format.
    /// </summary>
    /// <param name="componentName">The key of the component.</param>
    /// <returns>The standard claim string; or null if not found.</returns>
    internal string? GetSafeComponent(string componentName) {
        if (TryGetValue(componentName, out object? value)) {
            return SerializeComponent(value);
        }
        return null;
    }

    /// <summary>
    /// Get a date type component.
    /// </summary>
    /// <param name="componentName">The key of the component.</param>
    /// <returns>The standard component ; or null if not found.</returns>
    internal DateTime? GetSafeDate(string componentName) {
        if (TryGetValue(componentName, out object? value)) {
            return GetDate(value);
        }
        return null;
    }

    internal static DateTime? GetDate(object? value) {
        if (value is string @string) {
            if (long.TryParse(@string, out var unixTime)) {
                return DateTimeOffset.FromUnixTimeSeconds(unixTime).UtcDateTime;
            }
            if (DateTime.TryParseExact(@string, "r", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var date)) { // http header date format
                return date;
            }
        } else if (value is DateTime time) {
            return time;
        } else if (value is long @int) {
            return DateTimeOffset.FromUnixTimeSeconds(@int).UtcDateTime;
        }
        return null;
    }

    internal static string? SerializeComponent(object? value) {
        if (value == null) {
            return null;
        }
        if (value is string @string) {
            return @string.Length == 29 && DateTime.TryParse(value.ToString(), out var date) ? ((DateTimeOffset)date).ToUniversalTime().ToUnixTimeSeconds().ToString() : @string;
        } else if (value is DateTime time) {
            return ((DateTimeOffset)time).ToUniversalTime().ToUnixTimeSeconds().ToString();
        }
        return value.ToString();
    }

    /// <summary>
    /// Serializes this instance to string.
    /// </summary>
    /// <returns>This instance as an http header value.</returns>
    public override string ToString() => string.Join(",", this.Select(x => $"{x.Key.ToLowerInvariant()}=\"{SerializeComponent(x.Value)}\""));

    /// <summary>
    /// Parses the header value string into an <see cref="HttpSignature"/> instance.
    /// </summary>
    /// <param name="headerValue">The header value.</param>
    public static HttpSignature Parse(string headerValue) {
        var components = default(Dictionary<string, string>);
        try {
            components = headerValue.Split(',').Select(x => new {
                EqualsSignPosition = x.Trim().IndexOf('='),
                Value = x.Trim()
            })
            .ToDictionary(x => x.Value.Substring(0, x.EqualsSignPosition), x => x.Value.Substring(x.EqualsSignPosition + 1).Trim('"'));
        } catch {
            throw new FormatException($"Cannot parse HttpSignature from raw value {headerValue}");
        }
        var signature = new HttpSignature();
        foreach (var item in components) {
            if (signature.ContainsKey(item.Key)) {
                signature[item.Key] = item.Value;
            } else {
                signature.Add(item.Key, item.Value);
            }
        }
        return signature;
    }

    /// <summary>
    /// Validate the signature against the requested payload.
    /// </summary>
    /// <param name="key">The public key</param>
    /// <param name="digest"></param>
    /// <param name="requestId"></param>
    /// <param name="requestDate"></param>
    /// <param name="httpRequestTarget"></param>
    /// <param name="extraHeaderKeyValues">extra parameters to include</param>
    /// <returns></returns>
    public bool Validate(SecurityKey key, string digest, string requestId, DateTime requestDate, HttpRequestTarget httpRequestTarget, IDictionary<string, string>? extraHeaderKeyValues = null) {
        var headers = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase) {
            ["X-Request-Id"] = requestId,
            [HeaderFieldNames.Created] = requestDate.ToString("r"),
            [HttpDigest.HTTPHeaderName] = digest,
            [HttpRequestTarget.HeaderName] = httpRequestTarget.ToString()
        };
        if (extraHeaderKeyValues != null) {
            foreach (var item in extraHeaderKeyValues) {
                if (headers.ContainsKey(item.Key)) {
                    headers[item.Key] = item.Value;
                } else {
                    headers.Add(item.Key, item.Value);
                }
            }
        }
        return Validate(key, headers);
    }

    /// <summary>
    /// Validate the signature against the requested payload.
    /// </summary>
    /// <param name="key">The public key</param>
    /// <param name="requestUri"></param>
    /// <param name="requestMethod"></param>
    /// <param name="createdDate"></param>
    /// <param name="responseHeaders"></param>
    public bool Validate(SecurityKey key, Uri requestUri, string requestMethod, string createdDate, IEnumerable<KeyValuePair<string, IEnumerable<string>>> responseHeaders) {
        var headers = responseHeaders.ToDictionary(x => x.Key, x => x.Value.FirstOrDefault(), StringComparer.OrdinalIgnoreCase);
        var rawTarget = requestUri.PathAndQuery;
        headers.Add(HttpRequestTarget.HeaderName, new HttpRequestTarget(requestMethod, rawTarget).ToString());
        headers.Add(HeaderFieldNames.Created, createdDate);
        foreach (var header in headers) {
            Debug.WriteLine($"Http Signature: {header.Key}: {header.Value}");
        }
        return Validate(key, headers);
    }

    /// <summary>
    /// Validate the signature against the requested payload.
    /// </summary>
    /// <param name="key">The public key</param>
    /// <param name="headers"></param>
    public bool Validate(SecurityKey key, IDictionary<string, string?> headers) {
        var cryptoProviderFactory = key.CryptoProviderFactory;
        var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, InboundAlgorithmMap[Algorithm!]);
        try {
            var headersToValidate = Headers.Select(x => new KeyValuePair<string, string?>(x, headers[x]));
            var message = GenerateMessage(headersToValidate);
            return signatureProvider.Verify(Encoding.UTF8.GetBytes(message), Convert.FromBase64String(Signature!));
        } catch (KeyNotFoundException) {
            // A header is missing from the list. Although defined in the signature header names it is not present in the header values.
            return false;
        } finally {
            cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
        }
    }

    private static string GenerateMessage(IEnumerable<KeyValuePair<string, string?>> headerKeyValues) =>
        string.Join("\n", headerKeyValues.Where(x => x.Value != null).Select(x => $"{x.Key.ToLowerInvariant()}: {SerializeComponent(x.Value)}"));
}
