#if NET8_0
using System;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Indice.Cryptography;

/// <summary>
/// Polyfill DOTNET 8 
/// for loading X.509 certificates from various sources, including raw data and files, with support for both PEM and DER encodings, as well as PKCS#12 (PFX) blobs. This class provides a unified API for certificate loading across different platforms, abstracting away platform-specific details and limitations. The methods in this class may throw exceptions if the input data is invalid, the specified file cannot be found or accessed, or if the platform does not support certain key storage flags. Consumers should handle these exceptions appropriately when using the loading methods. 
/// </summary>
[UnsupportedOSPlatform("browser")]
public static class X509CertificateLoader
{
    /// <summary>
    /// Loads a single X.509 certificate (in either the PEM or DER encoding) from the specified raw data. 
    /// </summary>
    /// <param name="data"> The raw data to load. Cannot be null.</param>
    /// <returns>The certificate</returns>
    public static X509Certificate2 LoadCertificate(byte[] data) {
        // Detect PEM-encoded input (starts with "-----")
        if (data.Length > 5 && data[0] == '-') {
            return X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(data));
        }
        return new X509Certificate2(data);
    }

    /// <summary>
    /// Loads a single X.509 certificate (in either the PEM or DER encoding) from the specified raw data. 
    /// </summary>
    /// <param name="data"> The raw data to load. Cannot be null.</param>
    /// <returns>The certificate</returns>
    public static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> data) {
        // Detect PEM-encoded input (starts with "-----")
        if (data.Length > 5 && data[0] == '-') {
            return X509Certificate2.CreateFromPem(System.Text.Encoding.ASCII.GetString(data));
        }
        return new X509Certificate2(data);
    }

    /// <summary>
    /// Loads a single X.509 certificate (in either the PEM or DER encoding) from the specified file. 
    /// </summary>
    /// <param name="path"> The file system path to the certificate file to load. Cannot be null.</param>
    /// <returns>The certificate</returns>
    public static X509Certificate2 LoadCertificateFromFile(string path) => new (path);

    /// <summary>
    /// Loads a PKCS#12 (PFX) blob from the specified data and extracts an X.509 certificate using the provided password 
    /// </summary>
    /// <param name="data"> A byte array containing the PKCS#12 (PFX) data to load. Cannot be null.</param> 
    /// <param name="password"> A string representing the password used to decrypt the contents of the PFX. If the PFX is not password-protected, provide null or an empty string.</param>
    /// <param name="keyStorageFlags"> A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private key associated with the certificate. Must be valid for the current platform.</param>
    /// <returns>An X509Certificate2 object representing the loaded certificate. The certificate may include a private key if present in the PFX and importable with the specified flags.</returns>
    public static X509Certificate2 LoadPkcs12(byte[] data, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        => LoadPkcs12(data.AsSpan(), password.AsSpan(), keyStorageFlags);

    /// <summary>
    /// Loads a PKCS#12 (PFX) blob from the specified data and extracts an X.509 certificate using the provided password
    /// and key storage flags.
    /// </summary>
    /// <remarks>If loaderLimits is null, default loader limits are applied. The method may throw exceptions
    /// if the data is invalid, the password is incorrect, the key storage flags are not supported, or the loader limits
    /// are exceeded. Platform support for certain key storage flags may vary.</remarks>
    /// <param name="data">A read-only span containing the PKCS#12 (PFX) data to load. Cannot be null.</param>
    /// <param name="password">A read-only span containing the password used to decrypt the contents of the PFX. If the PFX is not
    /// password-protected, provide an empty span.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private key
    /// associated with the certificate.</param>
    /// <returns>An X509Certificate2 object representing the loaded certificate. The certificate may include a private key if
    /// present in the PFX and importable with the specified flags.</returns>
    public static X509Certificate2 LoadPkcs12(ReadOnlySpan<byte> data, ReadOnlySpan<char> password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        => new (data, password, keyStorageFlags);

    /// <summary>
    /// Loads the specified PKCS#12 (PFX) data and returns a collection containing all certificates found within the
    /// data.
    /// </summary>
    /// <param name="data" type="byte[]">A byte array containing the PKCS#12 (PFX) data to load. Cannot be null.</param>
    /// <param name="password"> A string representing the password used to decrypt the contents of the PFX. If the PFX is not password-protected, provide null or an empty string.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private keys associated with the certificates. Must be valid for the current platform.</param>
    /// <returns>An X509Certificate2Collection containing all certificates loaded from the provided PKCS#12 (PFX) data. The collection may be empty if no certificates are found.</returns>
    public static X509Certificate2Collection LoadPkcs12Collection(byte[] data, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) 
        => LoadPkcs12Collection(data.AsSpan(), password, keyStorageFlags);

    /// <summary>
    /// Loads the specified PKCS#12 (PFX) data and returns a collection containing all certificates found within the
    /// data.
    /// </summary>
    /// <remarks>If the loaderLimits parameter is provided, it restricts the import according to the specified
    /// limits. If loaderLimits is null, default limits are applied. This method may throw exceptions if the data is
    /// invalid, the password is incorrect, or the import operation violates platform or loader constraints.</remarks>
    /// <param name="data">A read-only span of bytes containing the PKCS#12 (PFX) data to load. Cannot be null.</param>
    /// <param name="password">A read-only span of characters representing the password used to decrypt the contents of the PFX. If the PFX is
    /// not password-protected, provide an empty span.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private keys
    /// associated with the certificates. Must be valid for the current platform.</param>
    /// <returns>An X509Certificate2Collection containing all certificates loaded from the provided PKCS#12 (PFX) data. The
    /// collection may be empty if no certificates are found.</returns>
    public static X509Certificate2Collection LoadPkcs12Collection(ReadOnlySpan<byte> data, ReadOnlySpan<char> password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) {
        // Create a collection to hold the certificates
        var certCollection = new X509Certificate2Collection();
        // Import certificates from the PFX file
        certCollection.Import(data, password, keyStorageFlags);
        return certCollection;

    }

    /// <summary>
    /// Loads all certificates from a PKCS#12 (PFX) file and returns them as a collection.
    /// </summary>
    /// <remarks>If the PKCS#12 file contains private keys, the specified key storage flags control
    /// how and where those keys are imported. The method may throw exceptions if the file is invalid, the password
    /// is incorrect, or the loader limits are exceeded.</remarks>
    /// <param name="path">The file path of the PKCS#12 (PFX) file to load. Cannot be null.</param>
    /// <param name="password">The password used to decrypt the PKCS#12 (PFX) file. May be null or empty if the file is not
    /// password-protected.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private keys
    /// associated with the certificates.</param>
    /// <returns>An X509Certificate2Collection containing all certificates found in the specified PKCS#12 (PFX) file. The
    /// collection may be empty if no certificates are present.</returns>
    public static X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, ReadOnlySpan<char> password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        => LoadPkcs12CollectionFromFile(path, password.ToString(), keyStorageFlags);

    /// <summary>
    /// Loads all certificates from a PKCS#12 (PFX) file and returns them as a collection.
    /// </summary>
    /// <remarks>If the PKCS#12 file contains private keys, the specified key storage flags control
    /// how and where those keys are imported. The method may throw exceptions if the file is invalid, the password
    /// is incorrect, or the loader limits are exceeded.</remarks>
    /// <param name="path">The file path of the PKCS#12 (PFX) file to load. Cannot be null.</param>
    /// <param name="password">The password used to decrypt the PKCS#12 (PFX) file. May be null or empty if the file is not
    /// password-protected.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that specifies where and how to import the private keys
    /// associated with the certificates.</param>
    /// <returns>An X509Certificate2Collection containing all certificates found in the specified PKCS#12 (PFX) file. The
    /// collection may be empty if no certificates are present.</returns>
    public static X509Certificate2Collection LoadPkcs12CollectionFromFile(string path, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet) {
        // Create a collection to hold the certificates
        var certCollection = new X509Certificate2Collection();
        // Import certificates from the PFX file
        certCollection.Import(path, password, keyStorageFlags);
        return certCollection;
    }

    /// <summary>
    /// Opens a PKCS#12 (PFX) file from the specified path and loads the contained X.509 certificate.
    /// </summary>
    /// <param name="path">The file system path to the PKCS#12 (PFX) file to open. Cannot be null.</param>
    /// <param name="password">The password used to decrypt the PKCS#12 (PFX) file. Specify null if the file is not password-protected.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that control where and how to import the private key
    /// associated with the certificate.</param>
    /// <returns>An X509Certificate2 object representing the loaded certificate.</returns>
    public static X509Certificate2 LoadPkcs12FromFile(string path, ReadOnlySpan<char> password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        => new (path, password, keyStorageFlags);

    /// <summary>
    /// Opens a PKCS#12 (PFX) file from the specified path and loads the contained X.509 certificate.
    /// </summary>
    /// <param name="path">The file system path to the PKCS#12 (PFX) file to open. Cannot be null.</param>
    /// <param name="password">The password used to decrypt the PKCS#12 (PFX) file. Specify null if the file is not password-protected.</param>
    /// <param name="keyStorageFlags">A bitwise combination of X509KeyStorageFlags values that control where and how to import the private key
    /// associated with the certificate.</param>
    /// <returns>An X509Certificate2 object representing the loaded certificate.</returns>
    public static X509Certificate2 LoadPkcs12FromFile(string path, string? password, X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.DefaultKeySet)
        => new (path, password, keyStorageFlags);
}
#endif