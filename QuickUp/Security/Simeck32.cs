namespace MircoGericke.Cryptography.Simeck;

using System.Buffers.Binary;

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using MircoGericke.Cryptography.Simeck.Manipulation;

public sealed class Simeck32 : IDisposable
{
	private const int NumberOfRounds = 32;
	private const int KeyLength = sizeof(ulong) / sizeof(ushort);
	private const int CipherLength = sizeof(int) / sizeof(ushort);

	private readonly Memory<ushort> keySchedule;

	public Simeck32(ulong key)
	{
		keySchedule = GenerateKeySchedule(key);
	}

	private static Memory<ushort> GenerateKeySchedule(ulong keyInput)
	{
		Span<ushort> key = stackalloc ushort[KeyLength];
		BinaryPrimitives.WriteUInt64LittleEndian(MemoryMarshal.Cast<ushort, byte>(key), keyInput);

		var schedule = new ushort[NumberOfRounds];

		// 2^sizeof(ushort) - 4
		ushort constant = 0xFFFC;

		uint polynomial = 0x9A42BB1F;

		for (var i = 0; i < NumberOfRounds; i++)
		{
			schedule[i] = key[0];

			constant = (ushort)(0xFFFC ^ (polynomial & 1));
			polynomial >>= 1;

			Round(constant, ref key[1], ref key[0]);

			SpanManipulation.RotateLeft(key[1..]);
		}

		key.Clear();

		return new(schedule);
	}

	public int Encrypt(int value)
	{
		Span<ushort> cipher = stackalloc ushort[CipherLength];
		BinaryPrimitives.WriteInt32LittleEndian(MemoryMarshal.Cast<ushort, byte>(cipher), value);

		var key = keySchedule.Span;

		for (var i = 0; i < NumberOfRounds; i++)
			Round(key[i], ref cipher[1], ref cipher[0]);

		var result = BinaryPrimitives.ReadInt32LittleEndian(MemoryMarshal.Cast<ushort, byte>(cipher));
		cipher.Clear();
		return result;
	}

	public int Decrypt(int value)
	{
		Span<ushort> cipher = stackalloc ushort[CipherLength];
		BinaryPrimitives.WriteInt32LittleEndian(MemoryMarshal.Cast<ushort, byte>(cipher), value);

		var keys = keySchedule.Span;

		for (var i = NumberOfRounds - 1; i >= 0; i--)
			Round(keys[i], ref cipher[0], ref cipher[1]);

		var result = BinaryPrimitives.ReadInt32LittleEndian(MemoryMarshal.Cast<ushort, byte>(cipher));
		cipher.Clear();
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Round(ushort k, ref ushort l, ref ushort r)
	{
		var temp = l;
		l = (ushort)(r ^ F(l) ^ k);
		r = temp;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ushort F(ushort x) => (ushort)((x & ushort.RotateLeft(x, 5)) ^ ushort.RotateLeft(x, 1));

	public void Dispose() => keySchedule.Span.Clear();
}
