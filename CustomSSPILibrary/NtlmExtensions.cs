using Microsoft.Data.SqlClient;

namespace CustomSSPILibrary;

public static class NtlmExtensions
{
    public static SqlConnection AddNtlmSupport(this SqlConnection connection)
    {
#if NET7_0_OR_GREATER
        connection.SSPIContextProviderFactory = () => new NegotiateAuthenticationSSPIContextProvider();
#else
        _ = new NetCoreReflectedNegotiateState("alksdjf", new("", ""), "");

        connection.SSPIContextProviderFactory = () => new ReflectedNegotiateStateSSPIContextProvider();
#endif

        return connection;
    }
}
