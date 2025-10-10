namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Http signatures builder interface
/// </summary>
public interface IHttpSignatureBuilder
{

    /// <summary>
    /// Gets the services.
    /// </summary>
    /// <value>
    /// The services.
    /// </value>
    IServiceCollection Services { get; }
}
