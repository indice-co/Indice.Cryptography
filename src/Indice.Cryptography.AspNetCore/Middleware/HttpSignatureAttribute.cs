using System;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// 
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, Inherited = true, AllowMultiple = false)]
public class HttpSignatureAttribute : Attribute
{
    /// <summary>
    /// Construct the signature attribute
    /// </summary>
    /// <param name="headerNames"></param>
    public HttpSignatureAttribute(params string[] headerNames) {
        HeaderNames = headerNames;
    }

    /// <summary>
    /// Header names taking part in the signature
    /// </summary>
    public string[] HeaderNames { get; }
}
