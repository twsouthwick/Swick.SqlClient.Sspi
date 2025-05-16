using Microsoft.Data.SqlClient;
using Swick.SqlClient.Sspi;

if (args is not [string connectionString])
{
    Console.WriteLine("Must supply at least a connection string");
    return;
}

using var sspiContextProvider = new NtlmSspiContextProvider();
using var sqlconnection = new SqlConnection(connectionString)
{
    SspiContextProvider = sspiContextProvider,
};

await sqlconnection.OpenAsync();

try
{
    var command = new SqlCommand("SELECT name FROM master.dbo.sysdatabases", sqlconnection);
    using var result = await command.ExecuteReaderAsync();

    Console.WriteLine("Success");
}
catch (Exception)
{
    Console.WriteLine("Failed");
}

