using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// The default http client validation keys store.
/// </summary>
public class DefaultHttpClientValidationKeysStore : IHttpClientValidationKeysStore
{
    /// <inheritdoc/>
    public Task<IEnumerable<SecurityKey>> GetValidationKeysAsync() =>
        Task.FromResult(Enumerable.Empty<SecurityKey>());
}