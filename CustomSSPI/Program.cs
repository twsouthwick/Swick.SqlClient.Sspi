using CustomSSPILibrary;
using Microsoft.Data.SqlClient;

var connectionString = "Server=localhost;User ID=someUser;Password=somePassword;Integrated Security=SSPI;Initial Catalog=master";

using var sqlconnection = new SqlConnection(connectionString)
    .AddNtlmSupport();

await sqlconnection.OpenAsync();

var command = new SqlCommand("SELECT name FROM master.dbo.sysdatabases", sqlconnection);
using var result = await command.ExecuteReaderAsync();

