namespace MircoGericke.Cryptography.Simeck;
using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using MircoGericke.Cryptography.Simeck.Manipulation;

public sealed class Simeck64 : IDisposable
{
	private const int NumberOfRounds = 44;
	private const int KeyLength = 16/*sizeof(Uint128)*/ / sizeof(uint);
	private const int CipherLength = sizeof(long) / sizeof(uint);

	private readonly Memory<uint> keySchedule;

	public Simeck64(in UInt128 key)
	{
		keySchedule = GenerateKeySchedule(key);
	}

	private static Memory<uint> GenerateKeySchedule(in UInt128 keyInput)
	{
		Span<uint> key = stackalloc uint[KeyLength];
		BinaryPrimitivesEx.WriteUInt128LittleEndian(MemoryMarshal.AsBytes(key), keyInput);

		var schedule = new uint[NumberOfRounds];

		// 2^sizeof(uint) - 4
		uint constant = 0xFFFFFFFC;
		ulong polynomial = 0x938BCA3083F;

		for (var i = 0; i < NumberOfRounds; i++)
		{
			schedule[i] = key[0];

			constant = (uint)(0xFFFFFFFC ^ (polynomial & 1));
			polynomial >>= 1;

			Round(constant, ref key[1], ref key[0]);

			SpanManipulation.RotateLeft(key[1..]);
		}

		key.Clear();

		return new(schedule);
	}

	public long Encrypt(in long value)
	{
		Span<uint> cipher = stackalloc uint[CipherLength];
		BinaryPrimitives.WriteInt64LittleEndian(MemoryMarshal.AsBytes(cipher), value);

		var key = keySchedule.Span;

		for (var i = 0; i < NumberOfRounds; i++)
			Round(key[i], ref cipher[1], ref cipher[0]);

		var result = BinaryPrimitives.ReadInt64LittleEndian(MemoryMarshal.AsBytes(cipher));
		cipher.Clear();
		return result;
	}

	public long Decrypt(in long value)
	{
		Span<uint> cipher = stackalloc uint[CipherLength];
		BinaryPrimitives.WriteInt64LittleEndian(MemoryMarshal.AsBytes(cipher), value);

		var keys = keySchedule.Span;

		for (var i = NumberOfRounds - 1; i >= 0; i--)
			Round(keys[i], ref cipher[0], ref cipher[1]);

		var result = BinaryPrimitives.ReadInt64LittleEndian(MemoryMarshal.AsBytes(cipher));
		cipher.Clear();
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(in uint k, ref uint l, ref uint r)
	{
		var temp = l;
		l = (r ^ F(l) ^ k);
		r = temp;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint F(in uint x) => (x & uint.RotateLeft(x, 5)) ^ uint.RotateLeft(x, 1);

	public void Dispose() => keySchedule.Span.Clear();
}