using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Http middleware that signs and validates Http signatures.
/// </summary>
public class HttpSignatureMiddleware
{
    // The middleware delegate to call after this one finishes processing.
    private readonly RequestDelegate _next;
    private readonly HttpSignatureOptions _options;
    private readonly ISystemClock _systemClock;

    /// <summary>
    /// construct the middleware
    /// </summary>
    /// <param name="next"></param>
    /// <param name="options"></param>
    /// <param name="systemClock"></param>
    public HttpSignatureMiddleware(
        RequestDelegate next,
        HttpSignatureOptions options,
        ISystemClock systemClock
    ) {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _systemClock = systemClock ?? throw new ArgumentNullException(nameof(systemClock));
    }

    /// <summary>
    /// Invokes the middleware.
    /// </summary>
    /// <param name="httpContext">Encapsulates all HTTP-specific information about an individual HTTP request.</param>
    /// <param name="logger">A generic interface for logging.</param>
    public async Task Invoke(HttpContext httpContext, ILogger<HttpSignatureMiddleware> logger) {
        var headerNames = new List<string>();
        var mustValidate = _options.RequestValidation && _options.TryMatch(httpContext, out headerNames);
        if (mustValidate || httpContext.Request.Headers.ContainsKey(HttpSignature.HTTPHeaderName)) {
            var rawSignature = httpContext.Request.Headers[HttpSignature.HTTPHeaderName];
            logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Raw Signature: {rawSignature}");
            var rawDigest = httpContext.Request.Headers[HttpDigest.HTTPHeaderName];
            logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Raw Digest: {rawDigest}");
            var rawCertificate = httpContext.Request.Headers[_options.RequestSignatureCertificateHeaderName];
            logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Raw Certificate: {rawCertificate}");
            if (string.IsNullOrWhiteSpace(rawSignature)) {
                var error = $"Missing httpSignature in HTTP header '{HttpSignature.HTTPHeaderName}'. Cannot validate signature.";
                await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                return;
            }

            var validationKeys = new List<SecurityKey>();
            if (!string.IsNullOrWhiteSpace(rawCertificate)) {
                // Case when the client sends the public key in the corresponding header
                X509Certificate2 cert;
                try {
                    cert = new X509Certificate2(Convert.FromBase64String(rawCertificate!));
                } catch {
                    var error = $"Signature Certificate not in a valid format. Expected a base64 encoded x509.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
                validationKeys.Add(new X509SecurityKey(cert));
            } else {
                // Case when the client does sends the public key, and we need to retrieve it from the client validation key store
                var clientValidationSecretsStore = httpContext.RequestServices.GetRequiredService<IHttpClientValidationKeysStore>();
                var clientSecrets = await clientValidationSecretsStore.GetValidationKeysAsync();
                if (!clientSecrets.Any()) {
                    var error = $"Missing certificate in HTTP header '{_options.RequestSignatureCertificateHeaderName}'. Cannot validate signature.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                    return;
                }
                validationKeys = clientSecrets.ToList();
            }

            logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Validation Keys: '{string.Join(", ", validationKeys.Select(x => x.KeyId))}'");
            var httpSignature = HttpSignature.Parse(rawSignature!);
            logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: HTTP Signature: {httpSignature}");
            var requestBody = Array.Empty<byte>();
            switch (httpContext.Request.Method) {
                case "POST":
                case "PUT":
                    requestBody = await GetRequestBody(httpContext.Request);
                    break;
                default:
                    break;
            }
            // Validate the request.
            if (httpSignature.Headers.Contains(HttpDigest.HTTPHeaderName)) {
                if (!string.IsNullOrWhiteSpace(rawSignature) && string.IsNullOrWhiteSpace(rawDigest)) {
                    var error = $"Missing digest in HTTP header '{HttpDigest.HTTPHeaderName}'. Cannot validate signature.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.BadRequest, error);
                    return;
                }
                var httpDigest = HttpDigest.Parse(rawDigest!);
                logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: HTTP Digest: {httpDigest}");
                var digestIsValid = httpDigest.Validate(requestBody);
                if (!digestIsValid) {
                    var error = $"Digest validation failed.";
                    await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                    return;
                }
            }

            var signatureIsValid = false;
            foreach (var validationKey in validationKeys) {
                if (httpSignature.Validate(validationKey, httpContext.Request)) {
                    signatureIsValid = true;
                    break;
                }
            }

            if (!signatureIsValid) {
                var error = $"Signature validation failed.";
                await WriteErrorResponse(httpContext, logger, HttpStatusCode.Unauthorized, error);
                return;
            }
            logger.LogInformation("Signature validated successfuly for path: '{0} {1}'", httpContext.Request.Method, httpContext.Request.Path);
            // Call the next middleware delegate in the pipeline.
        }
        if (mustValidate && _options.ResponseSigning == true) {
            using (var responseMemory = new MemoryStream()) {
                var originalStream = httpContext.Response.Body;
                httpContext.Response.Body = responseMemory;
                await _next.Invoke(httpContext);
                responseMemory.Seek(0, SeekOrigin.Begin);
                var content = responseMemory.ToArray();
                responseMemory.Seek(0, SeekOrigin.Begin);
                // Apply logic here for deciding which headers to add.
                var signingCredentialsStore = httpContext.RequestServices.GetRequiredService<IHttpSigningCredentialsStore>();
                var validationKeysStore = httpContext.RequestServices.GetRequiredService<IHttpValidationKeysStore>();
                var signingCredentials = await signingCredentialsStore.GetSigningCredentialsAsync();
                var validationKeys = await validationKeysStore.GetValidationKeysAsync();
                var validationKey = validationKeys.First() as X509SecurityKey;
                logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Validation Key: {validationKey!.KeyId}");
                var rawTarget = httpContext.GetPathAndQuery();
                logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Raw Target: {rawTarget}");
                var extraHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
                    [HttpRequestTarget.HeaderName] = new HttpRequestTarget(httpContext.Request.Method, rawTarget).ToString(),
                    [HttpDigest.HTTPHeaderName] = new HttpDigest(signingCredentials.Algorithm, content).ToString(),
                    [HeaderFieldNames.Created] = _systemClock.UtcNow.ToString("r"),
                    [_options.ResponseIdHeaderName] = Guid.NewGuid().ToString()
                };
                var includedHeaders = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
                foreach (var name in headerNames) {
                    if (httpContext.Response.Headers.ContainsKey(name)) {
                        if (includedHeaders.ContainsKey(name)) {
                            includedHeaders[name] = httpContext.Response.Headers[name]!;
                        } else {
                            includedHeaders.Add(name, httpContext.Response.Headers[name]!);
                        }
                    } else if (extraHeaders.ContainsKey(name)) {
                        if (name != HttpRequestTarget.HeaderName) {
                            var responseHeaderName = name == HeaderFieldNames.Created ? _options.ResponseCreatedHeaderName : name;
                            httpContext.Response.Headers.Append(responseHeaderName, extraHeaders[name]);
                        }
                        includedHeaders.Add(name, extraHeaders[name]);
                        logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: Added Header {name}: {includedHeaders[name]}");
                    }
                }
                var signature = new HttpSignature(signingCredentials, includedHeaders, null, null);
                httpContext.Response.Headers.Append(HttpSignature.HTTPHeaderName, signature.ToString());
                logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: {HttpSignature.HTTPHeaderName} Header: {signature}");
                httpContext.Response.Headers.Append(_options.ResponseSignatureCertificateHeaderName, Convert.ToBase64String(validationKey.Certificate.Export(X509ContentType.Cert)));
                // Go on with life.
                await responseMemory.CopyToAsync(originalStream);
                httpContext.Response.Body = originalStream;
            }
        } else {
            await _next.Invoke(httpContext);
        }
    }

    private async Task<byte[]> GetRequestBody(HttpRequest request) {
        request.EnableBuffering();
        using (var requestStream = new MemoryStream()) {
            await request.Body.CopyToAsync(requestStream);
            request.Body.Seek(0, SeekOrigin.Begin);
            return requestStream.ToArray();
        }
    }

    private static async Task WriteErrorResponse(HttpContext httpContext, ILogger<HttpSignatureMiddleware> logger, HttpStatusCode statusCode, string error) {
        logger.LogDebug($"{nameof(HttpSignatureMiddleware)}: {error}");
        logger.LogWarning(error);
        httpContext.Response.StatusCode = (int)statusCode;
        httpContext.Response.ContentType = "application/json";
        await httpContext.Response.WriteAsync(JsonSerializer.Serialize(new ProblemDetails() {
            Status = httpContext.Response.StatusCode,
            Title = $"{statusCode}",
            Detail = error
        }));
    }
}
