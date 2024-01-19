using Microsoft.Data.SqlClient;
using System.Buffers;
using System.Net.Security;

var connectionString = "Server=localhost;User ID=someUser;Password=somePassword;Integrated Security=SSPI;Initial Catalog=master";

using var sqlconnection = new SqlConnection(connectionString)
{
    SSPIContextProviderFactory = () => new CustomSSPIProvider(),
};

await sqlconnection.OpenAsync();

var command = new SqlCommand("SELECT name FROM master.dbo.sysdatabases", sqlconnection);
using var result = await command.ExecuteReaderAsync();

class CustomSSPIProvider : SSPIContextProvider
{
    private NegotiateAuthentication? _negotiateAuth = null;

    protected override IMemoryOwner<byte> GenerateSspiClientContext(ReadOnlyMemory<byte> received)
    {
        _negotiateAuth ??= new(new NegotiateAuthenticationClientOptions { Package = "Negotiate", TargetName = AuthenticationParameters.ServerName });

        var sendBuff = _negotiateAuth.GetOutgoingBlob(received.Span, out NegotiateAuthenticationStatusCode statusCode)!;

        if (statusCode is not NegotiateAuthenticationStatusCode.Completed and not NegotiateAuthenticationStatusCode.ContinueNeeded)
        {
            throw new InvalidOperationException($"Negotiate error: {statusCode}");
        }

        return new ArrayMemoryOwner(sendBuff);
    }
    private sealed class ArrayMemoryOwner : IMemoryOwner<byte>
    {
        private readonly byte[] _array;

        public ArrayMemoryOwner(byte[] array)
        {
            _array = array;
        }

        public Memory<byte> Memory => _array;

        public void Dispose()
        {
        }
    }
}
