using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Indice.Cryptography.AspNetCore.Features;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.WebUtilities;

namespace Microsoft.AspNetCore.Http;

/// <summary>
/// Represents an status 200 ok <see cref="IResult"/> for various cerificate types.
/// </summary>
public sealed class CertificateHttpResult : IResult, IEndpointMetadataProvider, IStatusCodeHttpResult, IFileHttpResult, IContentTypeHttpResult
{
    private readonly CertificateDetails _result;
    private readonly string _format;
    private readonly string? _password;
    private static readonly ReadOnlyDictionary<string, string> _formats = new ReadOnlyDictionary<string, string>(
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) {
            ["json"] = System.Net.Mime.MediaTypeNames.Application.Json,
            ["crt"] = "application/x-x509-user-cert", // The CRT extension is used for certificates. The certificates may be encoded as binary DER or as ASCII PEM.
            ["cer"] = "application/pkix-cert",  // Alternate form of .crt (Microsoft Convention). You can use MS to convert .crt to .cer (.both DER encoded .cer, or base64[PEM] encoded .cer)
            ["key"] = "application/pkcs8",      // The KEY extension is used both for public and private PKCS#8 keys. The keys may be encoded as binary DER or as ASCII PEM.
            ["pfx"] = "application/x-pkcs12"    // PFX.
        });
    /// <summary>
    /// The response content type.
    /// </summary>
    public string ContentType => _formats[_format];

    /// <summary>
    /// Gets the HTTP status code: <see cref="StatusCodes.Status200OK"/>
    /// </summary>
    public int StatusCode => StatusCodes.Status200OK;

    int? IStatusCodeHttpResult.StatusCode => StatusCode;

    string? IFileHttpResult.FileDownloadName => null;

    internal CertificateHttpResult(CertificateDetails result, string? format, string? password) {
        _result = result;
        _format = format is null || format.Equals(",") ? "json" : format;
        _password = password;
        if (!_formats.ContainsKey(_format)) {
            throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    ///<inheritdoc />
    public async Task ExecuteAsync(HttpContext httpContext) {
        using var stream = new FileBufferingWriteStream();
        using var streamWriter = new StreamWriter(stream, Encoding.ASCII);
        httpContext.Response.ContentType = ContentType;
        switch (ContentType) {
            case System.Net.Mime.MediaTypeNames.Application.Json:
                await JsonSerializer.SerializeAsync(stream, _result, typeof(CertificateDetails), new JsonSerializerOptions(JsonSerializerDefaults.Web));
                break;
            case "application/x-x509-user-cert":
            case "application/pkix-cert":
                //using (var streamWriter = new StreamWriter(stream, Encoding.ASCII)) {
                    await streamWriter.WriteAsync(_result.EncodedCert);
                    await streamWriter.FlushAsync();
                //}
                break;
            case "application/pkcs8":
                //using (var streamWriter = new StreamWriter(stream, Encoding.ASCII)) {
                    await streamWriter.WriteAsync(_result.PrivateKey);
                    await streamWriter.FlushAsync();
                //}
                break;
            case "application/x-pkcs12":
                var cert = new X509Certificate2(Encoding.ASCII.GetBytes(_result.EncodedCert));
                var privateKey = _result.PrivateKey.ReadAsRSAKey();
                var buffer = cert.CopyWithPrivateKey(RSA.Create(privateKey)).Export(X509ContentType.Pkcs12, _password);
                await stream.WriteAsync(buffer, 0, buffer.Length);
                cert.Dispose();
                httpContext.Response.Headers.Add("Content-Disposition", "attachment; filename=certificate.pfx");
                break;
            default: throw new Exception("Unsuported certificate format");
        }
        await stream.DrainBufferAsync(httpContext.Response.Body);
    }

    /// <inheritdoc/>
    static void IEndpointMetadataProvider.PopulateMetadata(MethodInfo method, EndpointBuilder builder) {
        ArgumentNullException.ThrowIfNull(method);
        ArgumentNullException.ThrowIfNull(builder);

        //builder.Metadata.Add(new ProducesResponseTypeMetadata(typeof(CertificateDetails), StatusCodes.Status200OK, System.Net.Mime.MediaTypeNames.Application.Json));
        builder.Metadata.Add(new ProducesResponseTypeMetadata(null, StatusCodes.Status200OK, System.Net.Mime.MediaTypeNames.Application.Json, _formats["crt"], _formats["cer"], _formats["key"], _formats["pfx"]));
    }
}

/// <summary>
/// Extesnion methods regarding certificates. <see cref="CertificateDetails"/> output in different file formats
/// </summary>
public static class CertificateHttpResultExtensions
{
    /// <summary>
    /// Creates an <see cref="IResult"/> that can handle different filetypes according to the file extension <paramref name="format"/>
    /// </summary>
    /// <param name="_"></param>
    /// <param name="result">The result object</param>
    /// <param name="format">The file extension without the dot. Accepts: crt, cer, key, pfx</param>
    /// <param name="password">Optional password in canse of <strong>pfx (Pkcs12)</strong></param>
    /// <returns></returns>
    public static CertificateHttpResult Certificate(this IResultExtensions _, CertificateDetails result, string? format, string? password = null)
        => new(result, format, password);


}
/// <summary>Equivalent to the .Produces call to add metadata to endpoints</summary>
internal sealed class ProducesResponseTypeMetadata : IProducesResponseTypeMetadata
{
    /// <summary>Constructor</summary>
    public ProducesResponseTypeMetadata(Type? type, int statusCode, string contentType, params string[] additionalContentTypes) {
        Type = type;
        StatusCode = statusCode;
        var list = new List<string>() { contentType };
        if (additionalContentTypes is not null) list.AddRange(additionalContentTypes);
        ContentTypes = list;
    }

    /// <summary>The clr type for the response body</summary>
    public Type? Type { get; }
    /// <summary>Http status code</summary>
    public int StatusCode { get; }
    /// <summary>Supported response body content types</summary>
    public IEnumerable<string> ContentTypes { get; }
}