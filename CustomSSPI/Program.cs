using Microsoft.Data.SqlClient;
using System.Buffers;

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
    protected override IMemoryOwner<byte> GenerateSspiClientContext(ReadOnlyMemory<byte> input)
    {
        throw new NotImplementedException();
    }
}
