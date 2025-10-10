namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// Encapsulates the (request-target) virtual header for the <see cref="HttpSignature"/>
/// </summary>
public class HttpRequestTarget
{
    /// <summary>
    /// The name in the headers list that this will appear.
    /// </summary>
    public const string HeaderName = "(request-target)";

    /// <summary>
    /// constructor
    /// </summary>
    /// <param name="httpMethod"></param>
    /// <param name="requestPath"></param>
    public HttpRequestTarget(string httpMethod, string requestPath) {
        HttpMethod = httpMethod;
        RequestPath = requestPath;
    }

    /// <summary>
    /// The http method in lowercase (post, put, get, delete, patch).
    /// </summary>
    public string HttpMethod { get; }

    /// <summary>
    /// the request path
    /// </summary>
    public string RequestPath { get; }

    /// <summary>
    /// string representation for the (request-target) header
    /// </summary>
    /// <returns></returns>
    public override string ToString() {
        return $"{HttpMethod.ToLowerInvariant()} {RequestPath}".Trim();
    }
}
