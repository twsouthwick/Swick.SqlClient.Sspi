using Microsoft.Data.SqlClient;
using System.Net;

namespace Swick.SqlClient.Sspi;

internal static class SspiAuthenticationParametersExtensions
{
    public static NetworkCredential CreateCredential(this SspiAuthenticationParameters authParams)
    {
        if (authParams is { UserId: { } userId, Password: { } password })
        {
            var idx = userId.IndexOf('\\');

            if (idx > 0)
            {
                var domain = userId.Substring(0, idx);
                var userName = userId.Substring(idx + 1);

                return new NetworkCredential(userName, password, domain);
            }
            else
            {
                return new NetworkCredential(userId, password);
            }
        }

        return new();
    }
}
