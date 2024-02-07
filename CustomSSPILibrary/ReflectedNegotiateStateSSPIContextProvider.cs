#if !NET7_0_OR_GREATER

using Microsoft.Data.SqlClient;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace CustomSSPILibrary;

internal sealed class ReflectedNegotiateStateSSPIContextProvider : SSPIContextProvider, IDisposable
{
    private NetCoreReflectedNegotiateState? _negotiate;

    public void Dispose()
    {
        _negotiate?.Dispose();
    }

    protected override IMemoryOwner<byte> GenerateSspiClientContext(ReadOnlyMemory<byte> input)
    {
        _negotiate ??= new ("NTLM", new NetworkCredential(AuthenticationParameters.UserId, AuthenticationParameters.Password), AuthenticationParameters.ServerName);

        var result = _negotiate.GetOutgoingBlob(input.Span.ToArray(), out var status, out var error);

        if (error is { })
        {
            throw error;
        }

        if (status == BlobErrorType.None)
        {
            return new ArrayMemoryOwner(result);
        }

        throw new InvalidOperationException($"Negotiate error: {status}");
    }
}

#endif
