using System.Diagnostics;

namespace Indice.Psd2.IdentityServer.Extensions;

internal static class StringExtensions
{
    [DebuggerStepThrough]
    public static string EnsureLeadingSlash(this string url) {
        if (!url.StartsWith("/")) {
            return "/" + url;
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string EnsureTrailingSlash(this string url) {
        if (!url.EndsWith("/")) {
            return url + "/";
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string RemoveLeadingSlash(this string url) {
        if (url != null && url.StartsWith("/")) {
            url = url.Substring(1);
        }

        return url;
    }

    [DebuggerStepThrough]
    public static string RemoveTrailingSlash(this string url) {
        if (url != null && url.EndsWith("/")) {
            url = url.Substring(0, url.Length - 1);
        }

        return url;
    }
}
