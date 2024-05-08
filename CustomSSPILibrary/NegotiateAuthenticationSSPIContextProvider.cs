#if NET7_0_OR_GREATER

using Microsoft.Data.SqlClient;
using System.Buffers;
using System.Net;
using System.Net.Security;

namespace CustomSSPILibrary;

internal sealed class NegotiateAuthenticationSSPIContextProvider : SSPIContextProvider
{
    private NegotiateAuthentication? _negotiateAuth = null;

    protected override void GenerateSspiClientContext(ReadOnlySpan<byte> incomingBlob, IBufferWriter<byte> outgoingBlobWriter)
    {
        _negotiateAuth ??= new(new NegotiateAuthenticationClientOptions
        {
            Package = "NTLM",
            TargetName = AuthenticationParameters.ServerName,
            Credential = new NetworkCredential(AuthenticationParameters.UserId, AuthenticationParameters.Password)
        });

        var sendBuff = _negotiateAuth.GetOutgoingBlob(incomingBlob, out NegotiateAuthenticationStatusCode statusCode)!;

        if (statusCode is not NegotiateAuthenticationStatusCode.Completed and not NegotiateAuthenticationStatusCode.ContinueNeeded)
        {
            throw new InvalidOperationException($"Negotiate error: {statusCode}");
        }

        outgoingBlobWriter.Write(sendBuff);
    }
}

#endif
