using System.Buffers;

namespace CustomSSPILibrary;

internal sealed class ArrayMemoryOwner(byte[] array) : IMemoryOwner<byte>
{
    private readonly byte[] _array = array;

    public Memory<byte> Memory => _array;

    public void Dispose()
    {
    }
}
