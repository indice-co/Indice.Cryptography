using System;
using Microsoft.EntityFrameworkCore;

namespace Indice.Cryptography.AspNetCore.Features.EF;

/// <summary>
/// DbContext for the IdentityServer operational data.
/// </summary>
/// <seealso cref="DbContext" />
public class CertificatesDbContext : DbContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificatesDbContext"/> class.
    /// </summary>
    /// <param name="options">The options.</param>
    /// <param name="storeOptions">The store options.</param>
    /// <exception cref="ArgumentNullException">storeOptions</exception>
    public CertificatesDbContext(DbContextOptions<CertificatesDbContext> options, CertificatesStoreOptions storeOptions)
        : base(options) {
        StoreOptions = storeOptions;
#if DEBUG
        Database.EnsureCreated();
#endif
    }

    /// <summary>
    /// Gets or sets the issued Certificates.
    /// </summary>
    /// <value>
    /// The issued Certificates.
    /// </value>
    public DbSet<DbCertificate> Certificates { get; set; }

    /// <summary>
    /// The options used to further customize the context
    /// </summary>
    protected CertificatesStoreOptions StoreOptions { get; }

    /// <summary>
    /// configures the model that was discovered by convention from the entity types
    /// </summary>
    /// <param name="modelBuilder">The builder being used to construct the model for this context. Databases (and other extensions) typically
    /// define extension methods on this object that allow you to configure aspects of the model that are specific
    /// to a given database.</param>
    /// <remarks>
    /// If a model is explicitly set on the options for this context (via <see cref="M:Microsoft.EntityFrameworkCore.DbContextOptionsBuilder.UseModel(Microsoft.EntityFrameworkCore.Metadata.IModel)" />)
    /// then this method will not be run.
    /// </remarks>
    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        modelBuilder.HasDefaultSchema(StoreOptions.DefaultSchema ?? "cert");
        
        modelBuilder.Entity<DbCertificate>(t => {
            t.ToTable("CertificateData");
            t.HasKey(x => x.KeyId);
        });
        base.OnModelCreating(modelBuilder);
    }
}
