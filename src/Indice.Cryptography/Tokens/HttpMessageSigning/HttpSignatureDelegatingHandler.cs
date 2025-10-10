using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.Tokens.HttpMessageSigning;

/// <summary>
/// Logging sent requests and received responses can help diagnose issues. This can easily be done with a custom delegating handler:
/// </summary>
public class HttpSignatureDelegatingHandler : DelegatingHandler
{
    /// <summary>
    /// Ignores the Response Validation 
    /// </summary>
    public bool IgnoreResponseValidation { get; set; } 
    /// <summary>
    /// The header name where the certificate used for signing the request will reside, in base64 encoding.  This header will be present in the request object if a signature is contained.
    /// </summary>
    public string RequestSignatureCertificateHeaderName { get; set; } = "TPP-Signature-Certificate";
    /// <summary>
    /// The header name where the certificate used for validating the response will reside, in base64 encoding.  This header will be present in the request object if a signature is contained.
    /// </summary>
    public static string ResponseSignatureCertificateHeaderName = "ASPSP-Signature-Certificate";
    /// <summary>
    /// The header name which corresponds to the (created) header name alias. Must be present in the request headers, if a signature is also contained. 
    /// </summary>
    public static string RequestCreatedHeaderName = "X-Date";
    /// <summary>
    /// The header name which corresponds to the (created) header name alias. Must be present in the request headers, if a signature is also contained. 
    /// </summary>
    public static string ResponseCreatedHeaderName = "X-Date";

    /// <summary>
    /// Creates a new instance of the <see cref="HttpSignatureDelegatingHandler"/> class with a specific inner handler.
    /// </summary>
    /// <param name="credential">Signing credentials used to sign outgoing requests.</param>
    /// <param name="headerNames">Header names to include in the <see cref="HttpSignature"/></param>
    public HttpSignatureDelegatingHandler(
        SigningCredentials credential,
        IEnumerable<string> headerNames
    ) : this(credential, headerNames, null) { }

    /// <summary>
    /// Creates a new instance of the <see cref="HttpSignatureDelegatingHandler"/> class with a specific inner handler.
    /// </summary>
    /// <param name="credential">Signing credentials used to sign outgoing requests.</param>
    /// <param name="headerNames">Header names to include in the <see cref="HttpSignature"/></param>
    /// <param name="innerHandler">The inner handler which is responsible for processing the HTTP response messages.</param>
    public HttpSignatureDelegatingHandler(
        SigningCredentials credential,
        IEnumerable<string> headerNames,
        HttpMessageHandler innerHandler
    ) : base(innerHandler ?? new HttpClientHandler()) {
        Credential = credential;
        HeaderNames = headerNames.ToArray();
    }

    /// <summary>
    /// Signing credentials used to sign outgoing requests.
    /// </summary>
    protected SigningCredentials Credential { get; }
    /// <summary>
    /// Header names to include in the <see cref="HttpSignature"/>.
    /// </summary>
    public string[] HeaderNames { get; }
    /// <summary>
    /// Paths that are excluded, optionally based on provided HTTP method.
    /// </summary>
    public IDictionary<string, string> IgnoredPaths { get; } = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

    /// <summary>
    /// Excludes a mapped path, optionally based on the given HTTP method. If HTTP method is not specified, every request to this path will not be used by <see cref="HttpSignatureDelegatingHandler"/>.
    /// </summary>
    /// <param name="path">The path to exclude.</param>
    /// <param name="httpMethods">The HTTP methods to exclude for the given path.</param>
    public void IgnorePath(string path, params string[] httpMethods) {
        if (path == null) {
            throw new ArgumentNullException(nameof(path), "Cannot ignore a null path.");
        }
        path = path.EnsureLeadingSlash().ToTemplatedDynamicPath();
        if (httpMethods?.Length == 0) {
            IgnoredPaths.Add(path, "*");
            return;
        }
        // Validate HTTP methods.
        foreach (var method in httpMethods) {
            var isValidHttpMethod = method.Equals("GET", StringComparison.OrdinalIgnoreCase)
                || method.Equals("POST", StringComparison.OrdinalIgnoreCase)
                || method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
                || method.Equals("DELETE", StringComparison.OrdinalIgnoreCase)
                || method.Equals("PATCH", StringComparison.OrdinalIgnoreCase);
            if (!isValidHttpMethod) {
                throw new ArgumentException($"HTTP method {method} is not valid.");
            }
        }
        var httpMethod = string.Join('|', httpMethods);
        IgnoredPaths.Add(path, httpMethod);
        return;
    }

    /// <summary>
    /// Sends an HTTP request to the inner handler to send to the server as an asynchronous operation.
    /// </summary>
    /// <param name="request">The HTTP request message to send to the server.</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns>The task object representing the asynchronous operation.</returns>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
        await SignRequest(request);
        var response = await base.SendAsync(request, cancellationToken);
        await ValidateResponse(request, response);
        return response;
    }

    private async Task ValidateResponse(HttpRequestMessage request, HttpResponseMessage response) {
        if (IgnoreResponseValidation) {
            return;
        }
        if (StringExtensions.IsIgnoredPath(IgnoredPaths, request.RequestUri.AbsolutePath, request.Method.Method)) {
            return;
        }
        if (!response.Headers.TryGetValues(HttpSignature.HTTPHeaderName, out var signatureValues) || signatureValues.Count() == 0) {
            return;
        }
        if (!response.Headers.TryGetValues(ResponseSignatureCertificateHeaderName, out var certValues) || certValues.Count() == 0) {
            var error = $"Missing certificate in HTTP header '{ResponseSignatureCertificateHeaderName}'. Cannot validate signature.";
            throw new Exception(error);
        }
        var rawSignature = signatureValues.First();
        var rawCertificate = certValues.First();
        Debug.WriteLine($"{nameof(HttpSignatureDelegatingHandler)}: Raw Signature: {rawSignature}");
        Debug.WriteLine($"{nameof(HttpSignatureDelegatingHandler)}: Raw Certificate: {rawCertificate}");
        X509Certificate2 certificate;
        try {
            certificate = new X509Certificate2(Convert.FromBase64String(rawCertificate));
        } catch (Exception inner) {
            var error = $"Signature Certificate not in a valid format. Expected a base64 encoded x509.";
            throw new Exception(error, inner);
        }
        var validationKey = new X509SecurityKey(certificate);
        Debug.WriteLine($"{nameof(HttpSignatureDelegatingHandler)}: Validation Key: {validationKey.KeyId}");
        var httpSignature = HttpSignature.Parse(rawSignature);
        if (response.Headers.TryGetValues(HttpDigest.HTTPHeaderName, out var digestValues) && digestValues.Count() > 0) {
            var rawDigest = digestValues.First();
            Debug.WriteLine($"{nameof(HttpSignatureDelegatingHandler)}: Raw Digest: {rawDigest}");
            var httpDigest = HttpDigest.Parse(rawDigest);
            Debug.WriteLine($"{nameof(HttpSignatureDelegatingHandler)}: Validated Token Digest: {httpDigest}");
            var responseBody = await response.Content.ReadAsByteArrayAsync();
            // Validate the request.
            var disgestIsValid = httpDigest.Validate(responseBody);
            if (!disgestIsValid) {
                var error = $"Response digest validation failed.";
                throw new Exception(error);
            }
        }
        response.Headers.TryGetValues(ResponseCreatedHeaderName, out var createdFieldValue);
        var signatureIsValid = httpSignature.Validate(validationKey, request.RequestUri, request.Method.Method, createdFieldValue.First(), response.Headers);
        if (!signatureIsValid) {
            var error = $"Response signature validation failed.";
            throw new Exception(error);
        }
    }

    private async Task SignRequest(HttpRequestMessage request) {
        if (StringExtensions.IsIgnoredPath(IgnoredPaths, request.RequestUri.AbsolutePath, request.Method.Method)) {
            return;
        }
        var content = request.Content != null ? (await request.Content.ReadAsByteArrayAsync()) : new byte[0];
        var validationKey = Credential.Key as X509SecurityKey;
        var pathAndQuery = Uri.UnescapeDataString(request.RequestUri.AbsolutePath) + request.RequestUri.Query;
        var headersToSign = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in HeaderNames) {
            if (HttpRequestTarget.HeaderName.Equals(name, StringComparison.OrdinalIgnoreCase)) {
                headersToSign.Add(HttpRequestTarget.HeaderName, new HttpRequestTarget(request.Method.Method, pathAndQuery).ToString());
                continue;
            } else if (HttpDigest.HTTPHeaderName.Equals(name, StringComparison.OrdinalIgnoreCase)) {
                headersToSign.Add(HttpDigest.HTTPHeaderName, new HttpDigest(Credential.Algorithm, content).ToString());
                request.Headers.Add(HttpDigest.HTTPHeaderName, headersToSign[name]);
                continue;
            } else if (HeaderFieldNames.Created.Equals(name, StringComparison.OrdinalIgnoreCase)) {
                headersToSign.Add(HeaderFieldNames.Created, request.Headers.TryGetValues(RequestCreatedHeaderName, out var createdDate) ? createdDate.First() : DateTimeOffset.UtcNow.ToString("r"));
                if (!request.Headers.Contains(RequestCreatedHeaderName)) {
                    request.Headers.Add(RequestCreatedHeaderName, headersToSign[HeaderFieldNames.Created]);
                }
                continue;
            } else {
                if (request.Headers.Contains(name)) {
                    var value = request.Headers.GetValues(name).FirstOrDefault();
                    if (headersToSign.ContainsKey(name)) {
                        headersToSign[name] = value;
                    } else {
                        headersToSign.Add(name, value);
                    }
                    Debug.WriteLine($"HttpSignature: Include '{name}: {value}'");
                } else {
                    throw new Exception($"HttpSignature: Cannot include header'{name}' it is missing from the request payload");
                }
            }
        }
        var signature = new HttpSignature(Credential, headersToSign, DateTime.UtcNow, null);
        request.Headers.Add(HttpSignature.HTTPHeaderName, signature.ToString());
        Debug.WriteLine($"HttpSignature: {HttpSignature.HTTPHeaderName} Header: {signature}");
        request.Headers.Add(RequestSignatureCertificateHeaderName, Convert.ToBase64String(validationKey.Certificate.Export(X509ContentType.Cert)));
    }
}
