namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// List of Signature header parameter names see: https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.
/// </summary>
public struct HttpSignatureParameterNames
{
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.1
    /// </summary>
    public const string KeyId = "keyId";
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.2
    /// </summary>
    public const string Signature = "signature";
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.3
    /// </summary>
    public const string Algorithm = "algorithm";
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.4
    /// </summary>
    public const string Created = "created";
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.5
    /// </summary>
    public const string Expires = "expires";
    /// <summary>
    /// see:https://tools.ietf.org/html/draft-cavage-http-signatures-11#section-2.1.6
    /// </summary>
    public const string Headers = "headers";
}
