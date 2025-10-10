namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// Special header names used to specify the list of HTTP headers included when generating the signature for the message.
/// </summary>
public class HeaderFieldNames
{
    /// <summary>
    /// Contains the creation time of the HTTP signature, expressed as a Unix timestamp integer value.
    /// </summary>
    public const string Created = "(created)";
    /// <summary>
    /// include the HTTP request target.
    /// </summary>
    public const string RequestTarget = "(request-target)";
    /// <summary>
    /// Contains the creation time of the HTTP signature, expressed as a Unix timestamp integer value..
    /// </summary>
    public const string Expires = "(expires)";
}
