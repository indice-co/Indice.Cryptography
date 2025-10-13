using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography.X509Certificates;

/// <summary>
/// Helps build a the subject for the <see cref="X500DistinguishedName"/> extention.
/// </summary>
public class SubjectBuilder
{
    private Dictionary<string, string> Subject { get; }

    /// <summary>
    /// Helps build a the subject for the <see cref="X500DistinguishedName"/> extention. Using fluent configuration.
    /// </summary>
    public SubjectBuilder() : this(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)) {
    }

    /// <summary>
    /// Initializes the subject builder using a list of key value pairs.
    /// </summary>
    public SubjectBuilder(Dictionary<string, string> subject) {
        Subject = subject;
    }

    /// <summary>
    /// Gets the value of one part of the subject by key.
    /// </summary>
    /// <param name="key">Key can any of the OU, O, C, E names etc.</param>
    /// <returns></returns>
    public string? this[string key] => GetValue(key);

    /// <summary>
    /// Get a value from the subject or null if there is none.
    /// </summary>
    /// <param name="key"></param>
    /// <returns></returns>
    public string? GetValue(string key) {
        return Subject.ContainsKey(key) ? Subject[key] : null;
    }

    /// <summary>
    /// Add whatever you like. Use with caution.
    /// </summary>
    /// <param name="key"></param>
    /// <param name="value"></param>
    /// <returns></returns>
    public SubjectBuilder Add(string key, string value) {
        Subject.Add(key, value);
        return this;
    }

    /// <summary>
    /// Adds CN 
    /// </summary>
    /// <param name="value"></param>
    /// <returns></returns>
    public SubjectBuilder AddCommonName(string value) {
        Subject.Add("CN", value);
        return this;
    }

    /// <summary>
    /// Ands O and OU
    /// </summary>
    /// <param name="organizationName"></param>
    /// <param name="organizationUnit"></param>
    /// <returns></returns>
    public SubjectBuilder AddOrganization(string organizationName, string organizationUnit) {
        Subject.Add("O", organizationName);
        Subject.Add("OU", organizationUnit);
        return this;
    }

    /// <summary>
    /// Adds C S &amp; L
    /// </summary>
    /// <param name="countryCode"></param>
    /// <param name="state"></param>
    /// <param name="city"></param>
    /// <returns></returns>
    public SubjectBuilder AddLocation(string countryCode, string? state = null, string? city = null) {
        Subject.Add("C", countryCode);
        if (!string.IsNullOrEmpty(state))
            Subject.Add("S", state);
        if (!string.IsNullOrEmpty(city))
            Subject.Add("L", city);
        return this;
    }

    /// <summary>
    /// Adds Email E
    /// </summary>
    /// <param name="email"></param>
    /// <returns></returns>
    public SubjectBuilder AddEmail(string email) {
        Subject.Add("E", email);
        return this;
    }

    /// <summary>
    /// Add User Identifier UID
    /// </summary>
    /// <param name="userIdentifier"></param>
    /// <returns></returns>
    public SubjectBuilder AddUserIdentifier(string userIdentifier) {
        Subject.Add("UID", userIdentifier);
        return this;
    }

    /// <summary>
    /// Add server domain component DC
    /// </summary>
    /// <param name="domainComponent"></param>
    /// <returns></returns>
    public SubjectBuilder AddDomainComponent(string domainComponent) {
        Subject.Add("DC", domainComponent);
        return this;
    }

    /// <summary>
    /// adds Organization identifier as it is identified by the 2.5.4.97 Oid
    /// </summary>
    /// <param name="id"></param>
    /// <returns></returns>
    public SubjectBuilder AddOrganizationIdentifier(string id) {
        Subject.Add("2.5.4.97", id);
        return this;
    }

    /// <summary>
    /// adds SERIALNUMBER (2.5.4.5 Oid)
    /// </summary>
    /// <param name="serialNumber"></param>
    /// <returns></returns>
    public SubjectBuilder AddSerialNumber(string serialNumber) {
        Subject.Add("SERIALNUMBER", serialNumber);
        return this;
    }


    /// <summary>
    /// Gets Organization identifier as it is identified by the 2.5.4.97 Oid
    /// </summary>
    /// <returns></returns>
    public string? GetOrganizationIdentifier() => GetValue("2.5.4.97") ?? GetValue("OID.2.5.4.97");

    /// <summary>
    /// Generate the <see cref="X500DistinguishedName"/>
    /// </summary>
    /// <param name="flags">Controls the delimiter</param>
    /// <returns></returns>
    public X500DistinguishedName Build(X500DistinguishedNameFlags flags = X500DistinguishedNameFlags.UseNewLines) {
        var delimiter = '\n';
        if (flags.HasFlag(X500DistinguishedNameFlags.UseNewLines)) {
            delimiter = '\n';
        } else if (flags.HasFlag(X500DistinguishedNameFlags.UseCommas)) {
            delimiter = ',';
        } else if (flags.HasFlag(X500DistinguishedNameFlags.UseSemicolons)) {
            delimiter = ';';
        }

        var name = string.Join(delimiter, [.. Subject.Select(x => $"{x.Key}={x.Value}")]);
        return new X500DistinguishedName(name, flags);
    }

    /// <summary>
    /// Parses the string representation of the <see cref="X500DistinguishedName"/> extention into an instance of the <see cref="SubjectBuilder"/> class.
    /// </summary>
    /// <param name="subject"></param>
    /// <returns></returns>
    public static SubjectBuilder Parse(string subject) {
        if (string.IsNullOrWhiteSpace(subject)) {
            throw new ArgumentException("Subject cannot be blank", nameof(subject));
        }
        return new SubjectBuilder(subject.Split(';', '\n', ',').Select(x => x.Split('=')).ToDictionary(x => x[0].Trim(), x => x[1]));
    }
}
