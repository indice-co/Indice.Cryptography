// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
#if NET9_0_OR_GREATER
using Duende.IdentityServer;
using Duende.IdentityServer.Configuration;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using Microsoft.Extensions.Options;
#else
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Validation;
using Microsoft.AspNetCore.Http;
#endif
using Indice.Psd2.IdentityServer.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Indice.Cryptography.Validation;

namespace Indice.Psd2.IdentityServer.Validation;

/// <summary>
/// Validates a secret based on RS256 signed JWT token
/// </summary>
public class Psd2PrivateKeyJwtSecretValidator : ISecretValidator
{
    private readonly Psd2IssuerSigningKeyValidator _issuerSigningKeyValidator;
    private readonly ILogger _logger;
    private readonly string _audienceUri;

#if NET9_0_OR_GREATER
    /// <summary>
    /// Instantiates an instance of private_key_jwt secret validator
    /// </summary>
    public Psd2PrivateKeyJwtSecretValidator(IOptions<IdentityServerOptions> options, Psd2IssuerSigningKeyValidator issuerSigningKeyValidator, ILogger<Psd2PrivateKeyJwtSecretValidator> logger) {
        _audienceUri = string.Concat(options.Value.IssuerUri?.EnsureTrailingSlash(), Constants.ProtocolRoutePaths.Token);
        _issuerSigningKeyValidator = issuerSigningKeyValidator;
        _logger = logger;
    }
#else
    /// <summary>
    /// Instantiates an instance of private_key_jwt secret validator
    /// </summary>
    public Psd2PrivateKeyJwtSecretValidator(IHttpContextAccessor contextAccessor, Psd2IssuerSigningKeyValidator issuerSigningKeyValidator, ILogger<Psd2PrivateKeyJwtSecretValidator> logger) {
        _audienceUri = string.Concat(contextAccessor.HttpContext.GetIdentityServerIssuerUri().EnsureTrailingSlash(), Constants.ProtocolRoutePaths.Token);
        _issuerSigningKeyValidator = issuerSigningKeyValidator;
        _logger = logger;
    }
#endif

    /// <summary>
    /// Validates a secret
    /// </summary>
    /// <param name="secrets">The stored secrets.</param>
    /// <param name="parsedSecret">The received secret.</param>
    /// <returns>
    /// A validation result
    /// </returns>
    /// <exception cref="System.ArgumentException">ParsedSecret.Credential is not a JWT token</exception>
    public Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets, ParsedSecret parsedSecret) {
        var fail = Task.FromResult(new SecretValidationResult { Success = false });
        var success = Task.FromResult(new SecretValidationResult { Success = true });

        if (parsedSecret.Type != IdentityServerConstants.ParsedSecretTypes.JwtBearer) {
            return fail;
        }

        var jwtTokenString = parsedSecret.Credential as string;

        if (jwtTokenString == null) {
            _logger.LogError("ParsedSecret.Credential is not a string.");
            return fail;
        }

        var enumeratedSecrets = secrets.ToList().AsReadOnly();

        List<SecurityKey> trustedKeys;
        try {
            trustedKeys = GetTrustedKeys(enumeratedSecrets);
        } catch (Exception e) {
            _logger.LogError(e, "Could not parse assertion as JWT token");
            return fail;
        }

        if (!trustedKeys.Any()) {
            _logger.LogError("There are no certificates available to validate client assertion.");
            return fail;
        }

        var tokenValidationParameters = new TokenValidationParameters {
            IssuerSigningKeys = trustedKeys,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyValidator = _issuerSigningKeyValidator.Validate,

            ValidIssuer = parsedSecret.Id,
            ValidateIssuer = true,

            ValidAudience = _audienceUri,
            ValidateAudience = true,

            RequireSignedTokens = true,
            RequireExpirationTime = true
        };
        try {
            var handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(jwtTokenString, tokenValidationParameters, out var token);

            var jwtToken = (JwtSecurityToken)token;

            if (jwtToken.Subject != jwtToken.Issuer) {
                _logger.LogError("Both 'sub' and 'iss' in the client assertion token must have a value of client_id.");
                return fail;
            }

            return success;
        } catch (Exception e) {
            _logger.LogError(e, "JWT token validation error");
            return fail;
        }
    }

    private List<SecurityKey> GetTrustedKeys(IReadOnlyCollection<Secret> secrets) {
        var trustedKeys = GetAllTrustedCertificates(secrets)
                            .Select(c => (SecurityKey)new X509SecurityKey(c))
                            .ToList();

        if (!trustedKeys.Any()
            && secrets.Any(s => s.Type == IdentityServerConstants.SecretTypes.X509CertificateThumbprint)) {
            _logger.LogWarning("Cannot validate client assertion token using only thumbprint. Client must be configured with X509CertificateBase64 secret.");
        }

        return trustedKeys;
    }

    private List<X509Certificate2> GetAllTrustedCertificates(IEnumerable<Secret> secrets) {
        return secrets
            .Where(s => s.Type == IdentityServerConstants.SecretTypes.X509CertificateBase64)
            .Select(s => GetCertificateFromString(s.Value))
            .Where(c => c != null)
            .Cast<X509Certificate2>()
            .ToList();
    }

    private X509Certificate2? GetCertificateFromString(string value) {
        try {
            return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(value));
        } catch {
            _logger.LogWarning("Could not read certificate from string: " + value);
            return null;
        }
    }
}