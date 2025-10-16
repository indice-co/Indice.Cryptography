using System;
using System.Collections.Generic;
using System.Linq;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Extensions on <see cref="HttpSignature"/>
/// </summary>
public static class HttpSignatureExtensions
{
    /// <summary>
    /// Validate the signature against the requested payload.
    /// </summary>
    /// <param name="signature"></param>
    /// <param name="key">The public key</param>
    /// <param name="httpRequest"></param>
    /// <returns></returns>
    public static bool Validate(this HttpSignature signature, SecurityKey key, HttpRequest httpRequest) {
        var headers = httpRequest.Headers.ToDictionary(x => x.Key, x => (string)x.Value!, StringComparer.OrdinalIgnoreCase);
        var options = (HttpSignatureOptions)httpRequest.HttpContext.RequestServices.GetService(typeof(HttpSignatureOptions))!;
        var forwardedPath = httpRequest.Headers[options.ForwardedPathHeaderName];
        string rawTarget = null!;
        if (!string.IsNullOrWhiteSpace(forwardedPath)) {
            rawTarget = forwardedPath!;
        } else {
            var requestFeature = httpRequest.HttpContext.Features.Get<IHttpRequestFeature>();
            rawTarget = $"{requestFeature!.Path}{requestFeature.QueryString}";
        }
        headers.Add(HttpRequestTarget.HeaderName, new HttpRequestTarget(httpRequest.Method, rawTarget).ToString());
        headers.Add(HeaderFieldNames.Created, httpRequest.Headers[options.RequestCreatedHeaderName]!);
        return signature.Validate(key, headers!);
    }

    /// <summary>
    /// Validate the signature against the requested payload.
    /// </summary>
    /// <param name="signature">The signature to validate.</param>
    /// <param name="key">The public key.</param>
    /// <param name="headers">The headers.</param>
    public static bool Validate(this HttpSignature signature, SecurityKey key, IDictionary<string, StringValues> headers) =>
        signature.Validate(key, headers.ToDictionary(x => x.Key, x => (string)x.Value!, StringComparer.OrdinalIgnoreCase)!);
}
