using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Indice.Cryptography.Tests;

public class HttpTokenIntegrationTests
{
    private readonly SigningCredentials _signingCredentials;
    private readonly HttpClient _client;
    private readonly IHost _host;

    public HttpTokenIntegrationTests() {
        _signingCredentials = CreateNewSigningCredentials();
        var host = Host.CreateDefaultBuilder().ConfigureWebHostDefaults(webBuilder => {
            webBuilder.UseContentRoot(Directory.GetCurrentDirectory())
                      .UseWebRoot(Directory.GetCurrentDirectory())
                      .UseTestServer()
                      .ConfigureServices(services => {
                          services.AddHttpSignatures(options => {
                              options.MapPath("/api/psd2", HeaderFieldNames.RequestTarget, HeaderFieldNames.Created, HttpDigest.HTTPHeaderName, "x-response-id");
                              options.IgnorePath("/api/psd2/payments/execute", HttpMethods.Get);
                              options.IgnorePath("/api/psd2/opendata", HttpMethods.Get);
                              options.IgnorePath("/api/psd2/other");
                              options.IgnorePath("/api/psd2/consents/{consentId}/status");
                              options.RequestValidation = true;
                              options.ResponseSigning = true;
                          })
                         .AddSigningCredential(_signingCredentials);
                      })
                      .Configure(app => {
                          app.UseRouting();
                          app.UseHttpSignatures();
                          app.UseEndpoints(endpoints => {
                              endpoints.MapGet("/api/psd2/payments", async context => {
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapGet("/api/psd2/payments/execute", async context => {
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapGet("/api/psd2/opendata/branches", async context => {
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapGet("/api/psd2/other/sub", async context => {
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapGet("/api/psd2/consents/{consentId}/status", async context => {
                                  var consentId = context.Request.RouteValues["consentId"];
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapPost("/api/psd2/consents/{consentId}/status", async context => {
                                  var consentId = context.Request.RouteValues["consentId"];
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                              endpoints.MapGet("/api/psd2/one/two/three", async context => {
                                  context.Response.Headers["Content-Type"] = "application/json;UTF-8";
                                  await context.Response.WriteAsync(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}");
                              });
                          });
                      });
        })
        .Build();
        _host = host;
        host.Start();
        var server = host.GetTestServer();
        var messageHandler = new HttpSignatureDelegatingHandler(
            credential: _signingCredentials,
            headerNames: ["(request-target)", "(created)", "digest", "x-request-id"],
            innerHandler: server.CreateHandler()
        );
        messageHandler.IgnorePath("api/psd2/payments/EXECUTE", HttpMethods.Get);
        messageHandler.IgnorePath("/api/psd2/opendata", HttpMethods.Get);
        messageHandler.IgnorePath("/api/psd2/other");
        messageHandler.IgnorePath("/api/psd2/consents/{consentId}/status");
        _client = new HttpClient(messageHandler) {
            BaseAddress = server.BaseAddress
        };
    }

    [Fact]
    public async Task HttpTokenIntegrationTest() {
        _client.DefaultRequestHeaders.Add("X-Date", DateTimeOffset.UtcNow.AddDays(-2).ToString("r"));
        _client.DefaultRequestHeaders.Add("X-Request-Id", Guid.NewGuid().ToString());
        var response = await _client.GetAsync("/api/psd2/payments?v=ΑΒΓ");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanIgnorePathWithSpecifiedMethod() {
        var response = await _client.GetAsync("/api/psd2/payments/execute");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanIgnoreSubPathWithSpecifiedMethod() {
        var response = await _client.GetAsync("/api/psd2/opendata/branches");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanIgnoreSubPathWithoutSpecifiedMethod() {
        var response = await _client.GetAsync("/api/psd2/other/sub");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanIgnoreDynamicPath() {
        var response = await _client.GetAsync("/api/psd2/consents/psd2:ais:hAQQYJQk3UW5uV00lfq9qg:Aa0ibG9jYWxob3N0/status");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanProcessDynamicPathWithSpecialCharacters() {
        _client.DefaultRequestHeaders.Add("X-Request-Id", "5f6f209b-78f8-4e8f-b429-2a0c20316ef9");
        var request = @"{""availableAccountTypes"":""AllAccountsWithBalances"",""recurringIndicator"":true,""validUntil"":""2021-07-11T17:48:27.9804584+00:00"",""frequencyPerDay"":5,""combinedServiceIndicator"":false}";
        var response = await _client.PostAsync("/api/psd2/consents/psd2:ais:hAQQYJQk3UW5uV00lfq9qg:Aa0ibG9jYWxob3N0/status", new StringContent(request, Encoding.UTF8, "application/json"));
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanProcessSameSizeDynamicPath() {
        _client.DefaultRequestHeaders.Add("X-Date", DateTimeOffset.UtcNow.AddDays(-2).ToString("r"));
        _client.DefaultRequestHeaders.Add("X-Request-Id", Guid.NewGuid().ToString());
        var response = await _client.GetAsync("/api/psd2/one/two/three");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }

    [Fact]
    public async Task CanIgnoreResponseValidation() {
        var server = _host.GetTestServer();
        var messageHandler = new HttpSignatureDelegatingHandler(
            credential: CreateNewSigningCredentials(),
            headerNames: ["(request-target)", "(created)", "digest", "x-request-id"],
            innerHandler: server.CreateHandler()
        );
        messageHandler.IgnoreResponseValidation = true;
        var client = new HttpClient(messageHandler) {
            BaseAddress = server.BaseAddress
        };
        client.DefaultRequestHeaders.Add("X-Date", DateTimeOffset.UtcNow.AddDays(-2).ToString("r"));
        client.DefaultRequestHeaders.Add("X-Request-Id", Guid.NewGuid().ToString());
        var response = await client.GetAsync("/api/psd2/one/two/three");
        var json = await response.Content.ReadAsStringAsync();
        Assert.Equal(@"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}", json);
    }


    private static SigningCredentials CreateNewSigningCredentials() {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=www.indice.gr",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(2)
        );

        return new SigningCredentials(
            new X509SecurityKey(cert),
            SecurityAlgorithms.RsaSha256Signature
        );
    }
}
