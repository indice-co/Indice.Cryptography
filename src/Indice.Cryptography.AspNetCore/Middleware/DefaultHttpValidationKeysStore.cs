using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// The default validation key store
/// </summary>
/// <seealso cref="IHttpValidationKeysStore" />
public class DefaultHttpValidationKeysStore : IHttpValidationKeysStore
{
    private readonly IEnumerable<SecurityKey> _keys;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultHttpValidationKeysStore"/> class.
    /// </summary>
    /// <param name="keys">The keys.</param>
    /// <exception cref="System.ArgumentNullException">keys</exception>
    public DefaultHttpValidationKeysStore(IEnumerable<SecurityKey> keys) {
        if (keys == null) throw new ArgumentNullException(nameof(keys));

        _keys = keys;
    }

    /// <summary>
    /// Gets all validation keys.
    /// </summary>
    /// <returns></returns>
    public Task<IEnumerable<SecurityKey>> GetValidationKeysAsync() {
        return Task.FromResult(_keys);
    }
}
