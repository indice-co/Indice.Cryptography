using System;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// National Competent Authority Id
/// PSD2 Authorization Number or other recognized identifier 
/// Examples "PSDPL-PFSA-1234567890" "PSDFI-FINFSA-1234567-8"  "PSDMT-MFSA-A 12345"
/// </summary>
[TypeConverter(typeof(NCAIdTypeConverter))]
public struct NCAId
{
    private const string REGEX_PATTERN = "(PSD)?([A-Z]{2})[-_]([A-Z]{2,8})([-_](.+))?";

    /// <summary>
    /// Construct from the distinct parts.
    /// </summary>
    /// <param name="prefix">PSD literal as a G-URN prefix (Optional)</param>
    /// <param name="twoLetterISOCountryCode"></param>
    /// <param name="supervisionAuthority"></param>
    /// <param name="pSPIdentifier"></param>
    public NCAId(string? prefix, string twoLetterISOCountryCode, string supervisionAuthority, string? pSPIdentifier) {
        Prefix = prefix;
        CountryCode = twoLetterISOCountryCode;
        SupervisionAuthority = supervisionAuthority;
        AuthorizationNumber = pSPIdentifier;
    }

    /// <summary>
    /// Checks to see if the code was parsed correctly
    /// </summary>
    public bool IsValid => !string.IsNullOrEmpty(CountryCode) && !string.IsNullOrEmpty(SupervisionAuthority) && !string.IsNullOrEmpty(AuthorizationNumber);

    /// <summary>
    /// &quot;PSD&quot; literal as a G-URN prefix (Optional)
    /// </summary>
    public string? Prefix { get; }

    /// <summary>
    /// 2 character ISO 3166-1 [8] country code representing the NCA country
    /// </summary>
    public string CountryCode { get; }
    /// <summary>
    /// 2-8 character NCA identifier without country code (A-Z uppercase only, no separator); 
    /// </summary>
    public string SupervisionAuthority { get; }
    /// <summary>
    /// PSP identifier (authorization number as specified by the NCA. There are no restrictions on the characters used). 
    /// </summary>
    public string? AuthorizationNumber   { get; }

    /// <summary>
    ///  PSP Identifier can contain prefix, followed by colon ":", including type of institution, as listed in
    ///  Credit institution – CI
    ///  Payment institution – PI 
    ///  Electronic money institution (or e-money institution) – EMI 
    ///  Account information service provider exempted under Article 33 of PSD2 – RAISP 
    /// </summary>
    public string InstitutionType {
        get {
            return string.IsNullOrEmpty(AuthorizationNumber) ? string.Empty :
                   AuthorizationNumber.StartsWith("CI:") ? "CI" :
                   AuthorizationNumber.StartsWith("PI:") ? "PI" :
                   AuthorizationNumber.StartsWith("EMI:") ? "EMI" : string.Empty;
        }
    }
    
    /// <summary>
    /// Discription for Type of institytion.
    /// PSP Identifier can contain prefix, followed by colon ":", including type of institution, as listed in
    /// Credit institution – CI
    /// Payment institution – PI 
    /// Electronic money institution (or e-money institution) – EMI 
    /// Account information service provider exempted under Article 33 of PSD2 – RAISP 
    /// </summary>
    public string InstitutionTypeDescription {
        get {
            switch (InstitutionType) {
                case "CI": return "Credit institution";
                case "PI": return "Payment institution";
                case "EMI": return "Electronic money institution (or e-money institution)";
                default: return string.Empty;
            }
        }
    }

    /// <summary>
    /// Convert back to string. Combining all parts.
    /// </summary>
    /// <returns></returns>
    public override string ToString() {
        return string.Join('-', new[] { $"{Prefix}{CountryCode}", SupervisionAuthority, AuthorizationNumber }.Where(x => !string.IsNullOrEmpty(x)));
    }

    /// <summary>
    /// Parses a text representation of National Competent Authority Id
    /// Examples: "PSDPL-PFSA-1234567890" "PSDFI-FINFSA-1234567-8"  "PSDMT-MFSA-A 12345"
    /// </summary>
    /// <param name="text">The input</param>
    /// <param name="throwOnError">When true the method will throw a <see cref="FormatException"/> if the <paramref name="text"/> 
    /// is not formated according to spec. Otherwize it will populate only the PSP identitfier part.</param>
    /// <returns></returns>
    public static NCAId Parse(string text, bool throwOnError = true) {
        var regex = new Regex(REGEX_PATTERN);
        if (!regex.IsMatch(text)) {
            if (throwOnError) { 
                throw new FormatException("Invalid PSD2 Authorization Number");
            } else {
                return new NCAId(null, null!, null!, text);
            }
        }
        var match = regex.Match(text);
        return new NCAId(match.Groups[1].Value, match.Groups[2].Value, match.Groups[3].Value, match.Groups[5].Value);
    }

    /// <summary>
    /// Try parse the given <paramref name="text"/> into a <paramref name="ncaId"/>. In case of exception it handles it and returns false
    /// </summary>
    /// <param name="text"></param>
    /// <param name="ncaId"></param>
    /// <returns>true in case of success</returns>
    public static bool TryParse(string text, out NCAId ncaId) {
        ncaId = default(NCAId);
        try {
            ncaId = Parse(text);
            return true;
        } catch {
            return false;
        }
    }


    /// <summary>
    /// Returns the hashcode for this instance
    /// </summary>
    /// <returns></returns>
    public override int GetHashCode() => (CountryCode ?? string.Empty).GetHashCode() ^
                                         (SupervisionAuthority ?? string.Empty).GetHashCode() ^
                                         (AuthorizationNumber ?? string.Empty).GetHashCode();

    /// <summary>
    /// Compare equality with the giver object. 
    /// </summary>
    /// <param name="obj"></param>
    /// <returns></returns>
    public override bool Equals(object? obj) {
        if (obj != null && obj is NCAId other) {
            return other.CountryCode == CountryCode &&
                   other.SupervisionAuthority == SupervisionAuthority &&
                   other.AuthorizationNumber == AuthorizationNumber;
        } else if (obj != null && obj is string text && TryParse(text, out other)) {
            return other.CountryCode == CountryCode &&
                   other.SupervisionAuthority == SupervisionAuthority &&
                   other.AuthorizationNumber == AuthorizationNumber;
        }
        return base.Equals(obj);
    }

    /// <summary>
    /// Cast Operator 
    /// </summary>
    /// <param name="value">the text to parse</param>
    public static explicit operator NCAId(string value) {
        if (string.IsNullOrEmpty(value)) return default(NCAId);
        return Parse(value, throwOnError: false);
    }
    
    /// <summary>
    /// Cast Operator 
    /// </summary>
    /// <param name="value">the text to parse</param>
    public static implicit operator string(NCAId value) => default(NCAId).Equals(value) ? null : value.ToString();
}

/// <summary>
/// Type converter for converting between <see cref="NCAId"/> and <seealso cref="string"/>
/// </summary>
public class NCAIdTypeConverter : TypeConverter
{
    /// <summary>
    /// Overrides can convert to declare support for string conversion.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="sourceType"></param>
    /// <returns></returns>
    public override bool CanConvertFrom(ITypeDescriptorContext? context, Type sourceType) {
        if (sourceType == typeof(string)) {
            return true;
        }

        return base.CanConvertFrom(context, sourceType);
    }

    /// <summary>
    /// Supply conversion from <see cref="string"/> to <seealso cref="NCAId"/> otherwise use default implementation
    /// </summary>
    /// <param name="context"></param>
    /// <param name="culture"></param>
    /// <param name="value"></param>
    /// <returns></returns>
    public override object? ConvertFrom(ITypeDescriptorContext? context, CultureInfo? culture, object value) {
        if (value is string) {
            return NCAId.Parse((string)value);
        }

        return base.ConvertFrom(context, culture, value);
    }

    /// <summary>
    /// Supply conversion from <see cref="NCAId"/> to <seealso cref="string"/> otherwise use default implementation
    /// </summary>
    /// <param name="context"></param>
    /// <param name="culture"></param>
    /// <param name="value"></param>
    /// <param name="destinationType"></param>
    /// <returns></returns>
    public override object? ConvertTo(ITypeDescriptorContext? context, CultureInfo? culture, object? value, Type destinationType) {
        if (destinationType == typeof(string)) {
            return ((NCAId)value!).ToString();
        }

        return base.ConvertTo(context, culture, value, destinationType);
    }
}

