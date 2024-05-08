using Microsoft.Data.SqlClient;

if (args is not [string connectionString])
{
    Console.WriteLine("Must supply at least a connection string");
    return;
}

using var sqlconnection = new SqlConnection(connectionString)
{
    SSPIContextProviderFactory = Ntlm.CreateLoggingProvider
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

