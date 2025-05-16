// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if NETFRAMEWORK

#pragma warning disable CA1810 // Initialize all static fields inline.

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Principal;

namespace Swick.SqlClient.Sspi;

/// <summary>
/// Adapted from NetCoreReflectedNegotiatedState to work on framework.
/// </remarks>
internal sealed class FrameworkReflectedNegotiateState : IDisposable
{
    private static readonly ConstructorInfo _constructor;
    private static readonly MethodInfo _getOutgoingBlob;
    private static readonly MethodInfo _closeContext;

    private readonly object _instance;

    static FrameworkReflectedNegotiateState()
    {
        var secAssembly = typeof(AuthenticationException).Assembly;
        var ntAuthType = secAssembly.GetType("System.Net.NTAuthentication", throwOnError: true)!;
        _constructor = ntAuthType.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(c => c.GetParameters().Length == 6)
            .Single();
        _getOutgoingBlob = ntAuthType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance).Where(info =>
            info.Name.Equals("GetOutgoingBlob") && info.GetParameters().Length == 3 && info.GetParameters()[0].ParameterType == typeof(byte[])).Single();
        _closeContext = ntAuthType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance).Where(info =>
            info.Name.Equals("CloseContext")).Single();
    }

    public FrameworkReflectedNegotiateState(string package, NetworkCredential credential, string spn)
    {
        // internal NTAuthentication(bool isServer, string package, NetworkCredential credential, string spn, ContextFlagsPal requestedContextFlags, ChannelBinding channelBinding)
        _instance = _constructor.Invoke([false, package, credential, spn, 0, null]);
    }

    public byte[] GetOutgoingBlob(byte[]? incomingBlob)
    {
        try
        {
            // byte[] GetOutgoingBlob(byte[] incomingBlob, bool throwOnError, out SecurityStatusPal statusCode)
            var parameters = new object?[] { incomingBlob, true, null };
            var blob = (byte[])_getOutgoingBlob.Invoke(_instance, parameters)!;

            return blob;
        }
        catch (TargetInvocationException tex)
        {
            // Unwrap
            ExceptionDispatchInfo.Capture(tex.InnerException!).Throw();
            throw;
        }
    }

    public void Dispose()
    {
        _closeContext.Invoke(_instance, Array.Empty<object>());
    }
}
#endif

