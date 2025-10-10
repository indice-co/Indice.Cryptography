using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Indice.Cryptography.AspNetCore.Middleware;

/// <summary>
/// Default signing credentials store
/// </summary>
/// <seealso cref="IHttpSigningCredentialsStore" />
public class DefaultHttpSigningCredentialsStore : IHttpSigningCredentialsStore
{
    private readonly SigningCredentials _credential;

    /// <summary>
    /// Initializes a new instance of the <see cref="DefaultHttpSigningCredentialsStore"/> class.
    /// </summary>
    /// <param name="credential">The credential.</param>
    public DefaultHttpSigningCredentialsStore(SigningCredentials credential) {
        _credential = credential;
    }

    /// <summary>
    /// Gets the signing credentials.
    /// </summary>
    /// <returns></returns>
    public Task<SigningCredentials> GetSigningCredentialsAsync() {
        return Task.FromResult(_credential);
    }
}
