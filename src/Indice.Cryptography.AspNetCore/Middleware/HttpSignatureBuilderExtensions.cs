using Indice.Cryptography.AspNetCore.Middleware;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods related to <see cref="IApplicationBuilder"/>
/// </summary>
public static class HttpSignatureBuilderExtensions
{
    /// <summary>
    /// Adds Http Message Signatures and validation to the <see cref="IApplicationBuilder"/> 
    /// request execution pipeline. Must be placed early on in the pipeline in order to catch the raw payload when validating
    /// and intercept the final response body when signing.
    /// </summary>
    /// <param name="builder"></param>
    /// <returns>The builder</returns>
    public static IApplicationBuilder UseHttpSignatures(this IApplicationBuilder builder) {
        return builder.UseMiddleware<HttpSignatureMiddleware>(new SystemClock());
    }
}
