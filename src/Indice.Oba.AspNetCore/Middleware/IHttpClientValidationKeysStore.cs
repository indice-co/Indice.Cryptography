using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Oba.AspNetCore.Middleware;

/// <summary>
/// Interface for the validation key store of the client.
/// </summary>
public interface IHttpClientValidationKeysStore
{
    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<SecurityKey>> GetValidationKeysAsync();
}