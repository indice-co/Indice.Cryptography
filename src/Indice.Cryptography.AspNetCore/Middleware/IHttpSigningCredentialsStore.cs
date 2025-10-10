using System.Threading.Tasks;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Interface for a signing credential store for <see cref="HttpSignature"/>
/// </summary>
public interface IHttpSigningCredentialsStore
{
    /// <summary>
    /// Gets the signing credentials.
    /// </summary>
    /// <returns></returns>
    Task<SigningCredentials> GetSigningCredentialsAsync();
}
