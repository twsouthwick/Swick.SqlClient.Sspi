#if !NETFRAMEWORK

using Microsoft.Data.SqlClient;
using System.Buffers;
using System.Net.Security;

namespace Swick.SqlClient.Sspi;

public class NtlmSspiContextProvider : SspiContextProvider, IDisposable
{
    private NegotiateAuthentication? _negotiateAuth = null;

    protected override bool GenerateContext(ReadOnlySpan<byte> incomingBlob, IBufferWriter<byte> outgoingBlobWriter, SspiAuthenticationParameters authParams)
    {
        _negotiateAuth ??= new(new NegotiateAuthenticationClientOptions()
        {
            Package = "NTLM",
            TargetName = authParams.Resource,
            Credential = authParams.CreateCredential()
        });

        var token = _negotiateAuth.GetOutgoingBlob(incomingBlob, out var statusCode)!;

        if (statusCode is NegotiateAuthenticationStatusCode.Completed or NegotiateAuthenticationStatusCode.ContinueNeeded)
        {
            outgoingBlobWriter.Write(token);
            return true;
        }

        _negotiateAuth.Dispose();
        _negotiateAuth = null;

        return false;
    }

    public void Dispose()
    {
        _negotiateAuth?.Dispose();
    }
}

#endif
