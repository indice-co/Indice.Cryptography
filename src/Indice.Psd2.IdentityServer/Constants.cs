namespace Indice.Psd2.IdentityServer;

internal static class Constants
{
    public static class ExtendedRoutePaths
    {
        public const string Totp = "totp";
    }

    public static class ProtocolRoutePaths
    {
        public const string ConnectPathPrefix = "connect";

        public const string Authorize = ConnectPathPrefix + "/authorize";
        public const string AuthorizeCallback = Authorize + "/callback";
        public const string DiscoveryConfiguration = ".well-known/openid-configuration";
        public const string DiscoveryWebKeys = DiscoveryConfiguration + "/jwks";
        public const string Token = ConnectPathPrefix + "/token";
        public const string Revocation = ConnectPathPrefix + "/revocation";
        public const string UserInfo = ConnectPathPrefix + "/userinfo";
        public const string Introspection = ConnectPathPrefix + "/introspect";
        public const string EndSession = ConnectPathPrefix + "/endsession";
        public const string EndSessionCallback = EndSession + "/callback";
        public const string CheckSession = ConnectPathPrefix + "/checksession";
        public const string DeviceAuthorization = ConnectPathPrefix + "/deviceauthorization";

        public const string MtlsPathPrefix = ConnectPathPrefix + "/mtls";
        public const string MtlsToken = MtlsPathPrefix + "/token";
        public const string MtlsRevocation = MtlsPathPrefix + "/revocation";
        public const string MtlsIntrospection = MtlsPathPrefix + "/introspect";
        public const string MtlsDeviceAuthorization = MtlsPathPrefix + "/deviceauthorization";

        public static readonly string[] CorsPaths =
        {
            DiscoveryConfiguration,
            DiscoveryWebKeys,
            Token,
            UserInfo,
            Revocation
        };
    }
}
