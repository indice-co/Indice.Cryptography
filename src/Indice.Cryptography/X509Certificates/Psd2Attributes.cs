using System.Linq;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// PSD2 Attributes (Psd2QcType)
/// </summary>
public class Psd2Attributes
{
    private bool[] _roles = new bool[4];
    /// <summary>
    /// account servicing (PSP_AS)
    /// </summary>
    public bool HasAccountServicing {
        get => _roles[0];
        set => _roles[0] = value;
    }
    /// <summary>
    /// payment initiation (PSP_PI) 
    /// </summary>
    public bool HasPaymentInitiation {
        get => _roles[1];
        set => _roles[1] = value;
    }
    /// <summary>
    /// account information (PSP_AI)
    /// </summary>
    public bool HasAccountInformation {
        get => _roles[2];
        set => _roles[2] = value;
    }
    /// <summary>
    /// issuing of card-based payment instruments (PSP_IC)
    /// </summary>
    public bool HasIssuingOfCardBasedPaymentInstruments {
        get => _roles[3];
        set => _roles[3] = value;
    }

    /// <summary>
    /// can be any of PSP_AS, PSP_PI, PSP_AI, PSP_IC
    /// </summary>
    public string[] Roles {
        get => new[] {
            _roles[0] ? "PSP_AS" : null,
            _roles[1] ? "PSP_PI" : null,
            _roles[2] ? "PSP_AI" : null,
            _roles[3] ? "PSP_IC" : null,
        }.Where(x => x != null).ToArray()!;
        set {
            _roles = new bool[4];
            if (value == null)
                return;
            foreach (var role in value) {
                switch (role) {
                    case "PSP_AS": _roles[0] = true; break;
                    case "PSP_PI": _roles[1] = true; break;
                    case "PSP_AI": _roles[2] = true; break;
                    case "PSP_IC": _roles[3] = true; break;
                }
            }
        }
    }

    /// <summary>
    /// NCAName - competent authority name
    /// </summary>
    public string? AuthorityName { get; set; }

    /// <summary>
    /// NCAId - PSD2 Authorization Number or other recognized identifier 
    /// </summary>
    public NCAId AuthorizationId { get; set; }
}

