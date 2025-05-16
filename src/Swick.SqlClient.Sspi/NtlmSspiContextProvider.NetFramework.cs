#if NETFRAMEWORK

using Microsoft.Data.SqlClient;
using System.Buffers;

namespace Swick.SqlClient.Sspi;

public class NtlmSspiContextProvider : SspiContextProvider, IDisposable
{
    private FrameworkReflectedNegotiateState? _negotiate;

    public void Dispose()
    {
        _negotiate?.Dispose();
    }

    protected override bool GenerateContext(ReadOnlySpan<byte> incomingBlob, IBufferWriter<byte> outgoingBlobWriter, SspiAuthenticationParameters authParams)
    {
        _negotiate ??= new("NTLM", authParams.CreateCredential(), authParams.Resource);

        try
        {
            outgoingBlobWriter.Write(_negotiate.GetOutgoingBlob(incomingBlob.ToArray()));
            return true;
        }
        catch (Exception)
        {
            _negotiate.Dispose();
            _negotiate = null;
            return false;
        }
    }
}

#endif
