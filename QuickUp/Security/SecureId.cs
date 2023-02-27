namespace QuickUp.Security;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
public static class SecureId
{


	public static long Deserialize64(ReadOnlySpan<char> value)
	{
		if (value.Length != Length64)
			ThrowInvalidId();

		Span<char> chars = stackalloc char[12];
		Span<byte> bytes = stackalloc byte[sizeof(long)];

		for (var i = 0; i < 11; i++)
		{
			chars[i] = value[i] switch
			{
				'-' => '+',
				'_' => '/',
				_ => value[i]
			};
		}

		chars[11] = '=';

		if (!Convert.TryFromBase64Chars(chars, bytes, out int _))
			ThrowInvalidId();

		return BitConverter.ToInt64(bytes);

		[DoesNotReturn]
		static void ThrowInvalidId() => throw new ArgumentException("Invalid id Format");
	}

	public const int Length64 = 11;

	public static long Generate()
	{
		Span<byte> bytes = stackalloc byte[sizeof(long)];
		RandomNumberGenerator.Fill(bytes);
		return BitConverter.ToInt64(bytes);
	}
}
