using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Extensions methods on <see cref="HttpContext"/>.
/// </summary>
public static class HttpContextExtensions
{
    /// <summary>
    /// Gets the path and query for the current <see cref="HttpContext"/>.
    /// </summary>
    /// <param name="httpContext">Encapsulates all HTTP-specific information about an individual HTTP request.</param>
    public static string GetPathAndQuery(this HttpContext httpContext) {
        var requestFeature = httpContext.Features.Get<IHttpRequestFeature>();
        var options = (HttpSignatureOptions)httpContext.RequestServices.GetService(typeof(HttpSignatureOptions));
        var forwardedPath = httpContext.Request.Headers[options.ForwardedPathHeaderName];
        if (!string.IsNullOrWhiteSpace(forwardedPath)) {
            return forwardedPath;
        }
        var uri = new Uri($"http://localhost{httpContext.Request.Path}{requestFeature.QueryString}", UriKind.Absolute);
        return uri.PathAndQuery;
    }
}
