namespace MircoGericke.Cryptography.Simeck.Manipulation;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static class BinaryPrimitivesEx
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void WriteUInt128LittleEndian(Span<byte> destination, UInt128 value)
	{
		if (!BitConverter.IsLittleEndian)
		{
			var tmp = ReverseEndianness(value);
			MemoryMarshal.Write(destination, ref tmp);
		}
		else
		{
			MemoryMarshal.Write(destination, ref value);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static UInt128 ReadUInt128LittleEndian(ReadOnlySpan<byte> source)
	{
		var result = MemoryMarshal.Read<UInt128>(source);
		if (!BitConverter.IsLittleEndian)
		{
			result = ReverseEndianness(result);
		}

		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static UInt128 ReverseEndianness(UInt128 value)
	{
		var span = MemoryMarshal.Cast<UInt128, ulong>(MemoryMarshal.CreateReadOnlySpan(ref value, 1));

		return new(
			BinaryPrimitives.ReverseEndianness(span[0]),
			BinaryPrimitives.ReverseEndianness(span[1])
		);
	}
}
