using System.ComponentModel.DataAnnotations;
using Indice.Cryptography.X509Certificates;

namespace Indice.Cryptography;

/// <summary>
/// Represents Data required in order to create a certificate.
/// </summary>
public class Psd2CertificateRequest
{
    /// <summary>
    /// The city
    /// </summary>
    [Required]
    public string City { get; set; } = null!;

    /// <summary>
    /// The state name
    /// </summary>
    [Required]
    public string State { get; set; } = null!;

    /// <summary>
    /// The coutntry code two letter ISO (ie GR, FR, ES, DE ...)
    /// </summary>
    [Required]
    public string CountryCode { get; set; } = null!;

    /// <summary>
    /// The legal name of the organization the the cerificate is issued to.
    /// </summary>
    [Required]
    public string Organization { get; set; } = null!;

    /// <summary>
    /// The organization unit that the cerificate is issued to.
    /// </summary>
    [Required]
    public string OrganizationUnit { get; set; } = null!;

    /// <summary>
    /// The domain name of the organizition where this certificate will be used.
    /// </summary>
    [Required]
    public string CommonName { get; set; } = null!;

    /// <summary>
    /// The National Competent Authority Code (ie BOG is the code for "Bank of Greece")
    /// </summary>
    [Required]
    public string AuthorityId { get; set; } = null!;

    /// <summary>
    /// The National Competent Authority name (ie "Bank of Greece")
    /// </summary>
    [Required]
    public string AuthorityName { get; set; } = null!;

    /// <summary>
    /// The Authorization number for the PSP
    /// </summary>
    [Required]
    public string AuthorizationNumber { get; set; } = null!;

    /// <summary>
    /// The validity period from today in number of days
    /// </summary>
    public int ValidityInDays { get; set; } = 365;

    /// <summary>
    /// Roles of the PSD2 PSP 
    /// </summary>
    [Required]
    public Psd2RoleFlags Roles { get; set; } = new Psd2RoleFlags();

    /// <summary>
    /// QC type identifiers QWAC QSEAL etc.
    /// </summary>
    public QcTypeIdentifiers QcType { get; set; } = QcTypeIdentifiers.Web;

    /// <summary>
    /// Wrapper class that holds requested Role flags to be included in the certificate.
    /// </summary>
    public class Psd2RoleFlags
    {
        /// <summary>
        /// Account Information
        /// </summary>
        public bool Aisp { get; set; }

        /// <summary>
        /// Account Servicing
        /// </summary>
        public bool Aspsp { get; set; }

        /// <summary>
        /// Payment Initiation
        /// </summary>
        public bool Pisp { get; set; }

        /// <summary>
        /// Issuing of card based payment instruments
        /// </summary>
        public bool Piisp { get; set; }
    }

    /// <summary>
    /// Creates an example request filld with test data.
    /// </summary>
    /// <returns></returns>
    public static Psd2CertificateRequest Example() {
        return new Psd2CertificateRequest {
            City = "Athens",
            State = "Attiki",
            CountryCode = "GR",
            Organization = "INDICE OE",
            OrganizationUnit = "WEB",
            CommonName = "www.indice.gr",
            AuthorityId = "BOG",
            AuthorityName = "Bank of Greece",
            AuthorizationNumber = "800000005",
            ValidityInDays = 365,
            Roles = new Psd2RoleFlags {
                Aisp = true,
                Aspsp = true,
                Piisp = true,
                Pisp = true,
            }
        };
    }
}
