using Microsoft.Data.SqlClient;
using System.Buffers;

namespace Swick.SqlClient;

public static class Ntlm
{
    public static SSPIContextProvider CreateProvider()
    {
#if NET7_0_OR_GREATER
        return new NegotiateAuthenticationSSPIContextProvider();
#else
        return new ReflectedNegotiateStateSSPIContextProvider();
#endif
    }

    public static SSPIContextProvider CreateLoggingProvider() => new LoggingProvider();

    private sealed class LoggingProvider
#if NET7_0_OR_GREATER
        : NegotiateAuthenticationSSPIContextProvider
#else
        : ReflectedNegotiateStateSSPIContextProvider
#endif
    {
        private bool _initialized;

        protected override void GenerateSspiClientContext(ReadOnlySpan<byte> incomingBlob, IBufferWriter<byte> outgoingBlobWriter)
        {
            if (!_initialized)
            {
                Console.WriteLine($"Type: {GetType().BaseType!.Name}");
                Console.WriteLine($"User: {AuthenticationParameters.UserId}");
                Console.WriteLine($"Server: {AuthenticationParameters.UserId}");
                Console.WriteLine($"Password {!string.IsNullOrEmpty(AuthenticationParameters.Password)}");
            }

            Console.WriteLine($"Incoming blob: {Convert.ToBase64String(incomingBlob.ToArray())}");

            ArrayBufferWriter<byte> b = new();
            base.GenerateSspiClientContext(incomingBlob, b);

            Console.WriteLine($"Outgoing blob: {Convert.ToBase64String(b.WrittenMemory.ToArray())}");

            outgoingBlobWriter.Write(b.WrittenSpan);
        }
    }
}
