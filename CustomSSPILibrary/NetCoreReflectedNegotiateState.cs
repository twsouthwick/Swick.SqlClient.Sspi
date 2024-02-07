// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !NET7_0_OR_GREATER

#pragma warning disable CA1810 // Initialize all static fields inline.

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Principal;

namespace CustomSSPILibrary;

/// <summary>
/// Taken from https://github.com/dotnet/aspnetcore/blob/ce92289ad77acd98cd6deab6c41b7fe0277cef83/src/Security/Authentication/Negotiate/src/Internal/ReflectedNegotiateState.cs
/// </summary>
/// <remarks>
/// This class is no longer in ASP.NET Core as .NET 7 introduced a public API for NTAuthenticate. However, this was used in ASP.NET Core in production to handle authentication, so
/// is probably ok to use for those runtimes.
/// 
/// NOTE: the original code was written as a way to use the underlying NTAuthenticate in 'server' mode, while we need to use it as 'client'. An attempt has been made to take
/// that into account, but has not been fully tested.
/// </remarks>
internal sealed class NetCoreReflectedNegotiateState : IDisposable
{
    // https://www.gnu.org/software/gss/reference/gss.pdf
    private const uint GSS_S_NO_CRED = 7 << 16;

    private static readonly ConstructorInfo _constructor;
    private static readonly MethodInfo _getOutgoingBlob;
    private static readonly MethodInfo _closeContext;
    private static readonly FieldInfo _statusCode;
    private static readonly FieldInfo _statusException;
    private static readonly MethodInfo _getException;

#if NET
    private static readonly FieldInfo? _gssMinorStatus;
    private static readonly Type? _gssExceptionType;
#endif

    private readonly object _instance;

    static NetCoreReflectedNegotiateState()
    {
        var secAssembly = typeof(AuthenticationException).Assembly;
        var ntAuthType = secAssembly.GetType("System.Net.NTAuthentication", throwOnError: true)!;
        _constructor = ntAuthType.GetConstructors(BindingFlags.NonPublic | BindingFlags.Instance).First();
        _getOutgoingBlob = ntAuthType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance).Where(info =>
            info.Name.Equals("GetOutgoingBlob") && info.GetParameters().Length == 3 && info.GetParameters()[0].ParameterType == typeof(byte[])).Single();
        _closeContext = ntAuthType.GetMethods(BindingFlags.NonPublic | BindingFlags.Instance).Where(info =>
            info.Name.Equals("CloseContext")).Single();

        var securityStatusType = secAssembly.GetType("System.Net.SecurityStatusPal", throwOnError: true)!;
        _statusCode = securityStatusType.GetField("ErrorCode")!;
        _statusException = securityStatusType.GetField("Exception")!;

#if NET
        if (!OperatingSystem.IsWindows())
        {
            var interopType = secAssembly.GetType("Interop", throwOnError: true)!;
            var netNativeType = interopType.GetNestedType("NetSecurityNative", BindingFlags.NonPublic | BindingFlags.Static)!;
            _gssExceptionType = netNativeType.GetNestedType("GssApiException", BindingFlags.NonPublic)!;
            _gssMinorStatus = _gssExceptionType.GetField("_minorStatus", BindingFlags.Instance | BindingFlags.NonPublic)!;
        }
#endif

        var negoStreamPalType = secAssembly.GetType("System.Net.Security.NegotiateStreamPal", throwOnError: true)!;
        _getException = negoStreamPalType.GetMethods(BindingFlags.NonPublic | BindingFlags.Static).Where(info =>
            info.Name.Equals("CreateExceptionFromError")).Single();
    }

    public NetCoreReflectedNegotiateState(string package, NetworkCredential credential, string spn)
    {
        // internal NTAuthentication(bool isServer, string package, NetworkCredential credential, string spn, ContextFlagsPal requestedContextFlags, ChannelBinding channelBinding)
        _instance = _constructor.Invoke(new object?[] { false, package, credential, spn, 0, null });
    }

    public byte[] GetOutgoingBlob(byte[]? incomingBlob, out BlobErrorType status, out Exception? error)
    {
        try
        {
            // byte[] GetOutgoingBlob(byte[] incomingBlob, bool throwOnError, out SecurityStatusPal statusCode)
            var parameters = new object?[] { incomingBlob, false, null };
            var blob = (byte[])_getOutgoingBlob.Invoke(_instance, parameters)!;

            var securityStatus = parameters[2];
            // TODO: Update after corefx changes
            error = (Exception?)(_statusException.GetValue(securityStatus)
                ?? _getException.Invoke(null, new[] { securityStatus }));
            var errorCode = (SecurityStatusPalErrorCode)_statusCode.GetValue(securityStatus)!;

#if NET
            // TODO: Remove after corefx changes
            // The linux implementation always uses InternalError;
            if (errorCode == SecurityStatusPalErrorCode.InternalError
                && !OperatingSystem.IsWindows()
                && _gssExceptionType!.IsInstanceOfType(error))
            {
                var majorStatus = (uint)error.HResult;
                var minorStatus = (uint)_gssMinorStatus!.GetValue(error)!;

                // Remap specific errors
                if (majorStatus == GSS_S_NO_CRED && minorStatus == 0)
                {
                    errorCode = SecurityStatusPalErrorCode.UnknownCredentials;
                }

                error = new Exception($"An authentication exception occurred (0x{majorStatus:X}/0x{minorStatus:X}).", error);
            }
#endif

            if (errorCode == SecurityStatusPalErrorCode.OK
                || errorCode == SecurityStatusPalErrorCode.ContinueNeeded
                || errorCode == SecurityStatusPalErrorCode.CompleteNeeded)
            {
                status = BlobErrorType.None;
            }
            else if (IsCredentialError(errorCode))
            {
                status = BlobErrorType.CredentialError;
            }
            else if (IsClientError(errorCode))
            {
                status = BlobErrorType.ClientError;
            }
            else
            {
                status = BlobErrorType.Other;
            }

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

    private static bool IsCredentialError(SecurityStatusPalErrorCode error)
    {
        return error == SecurityStatusPalErrorCode.LogonDenied ||
            error == SecurityStatusPalErrorCode.UnknownCredentials ||
            error == SecurityStatusPalErrorCode.NoImpersonation ||
            error == SecurityStatusPalErrorCode.NoAuthenticatingAuthority ||
            error == SecurityStatusPalErrorCode.UntrustedRoot ||
            error == SecurityStatusPalErrorCode.CertExpired ||
            error == SecurityStatusPalErrorCode.SmartcardLogonRequired ||
            error == SecurityStatusPalErrorCode.BadBinding;
    }

    private static bool IsClientError(SecurityStatusPalErrorCode error)
    {
        return error == SecurityStatusPalErrorCode.InvalidToken ||
            error == SecurityStatusPalErrorCode.CannotPack ||
            error == SecurityStatusPalErrorCode.QopNotSupported ||
            error == SecurityStatusPalErrorCode.NoCredentials ||
            error == SecurityStatusPalErrorCode.MessageAltered ||
            error == SecurityStatusPalErrorCode.OutOfSequence ||
            error == SecurityStatusPalErrorCode.IncompleteMessage ||
            error == SecurityStatusPalErrorCode.IncompleteCredentials ||
            error == SecurityStatusPalErrorCode.WrongPrincipal ||
            error == SecurityStatusPalErrorCode.TimeSkew ||
            error == SecurityStatusPalErrorCode.IllegalMessage ||
            error == SecurityStatusPalErrorCode.CertUnknown ||
            error == SecurityStatusPalErrorCode.AlgorithmMismatch ||
            error == SecurityStatusPalErrorCode.SecurityQosFailed ||
            error == SecurityStatusPalErrorCode.UnsupportedPreauth;
    }
}

internal enum SecurityStatusPalErrorCode
{
    NotSet = 0,
    OK,
    ContinueNeeded,
    CompleteNeeded,
    CompAndContinue,
    ContextExpired,
    CredentialsNeeded,
    Renegotiate,

    // Errors
    OutOfMemory,
    InvalidHandle,
    Unsupported,
    TargetUnknown,
    InternalError,
    PackageNotFound,
    NotOwner,
    CannotInstall,
    InvalidToken,
    CannotPack,
    QopNotSupported,
    NoImpersonation,
    LogonDenied,
    UnknownCredentials,
    NoCredentials,
    MessageAltered,
    OutOfSequence,
    NoAuthenticatingAuthority,
    IncompleteMessage,
    IncompleteCredentials,
    BufferNotEnough,
    WrongPrincipal,
    TimeSkew,
    UntrustedRoot,
    IllegalMessage,
    CertUnknown,
    CertExpired,
    DecryptFailure,
    AlgorithmMismatch,
    SecurityQosFailed,
    SmartcardLogonRequired,
    UnsupportedPreauth,
    BadBinding,
    DowngradeDetected,
    ApplicationProtocolMismatch
}

internal enum BlobErrorType
{
    None,
    CredentialError,
    ClientError,
    Other
}

#endif