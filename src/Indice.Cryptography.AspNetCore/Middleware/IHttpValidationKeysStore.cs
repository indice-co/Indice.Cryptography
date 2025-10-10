using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Interface for the validation key store
/// </summary>
public interface IHttpValidationKeysStore
{
    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    Task<IEnumerable<SecurityKey>> GetValidationKeysAsync();
}
