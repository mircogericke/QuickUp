namespace QuickUp.Security;

using MircoGericke.Cryptography.Simeck;
using System.Diagnostics.CodeAnalysis;

public class SecureId64
{
	private readonly QuickUpConfiguration configuration;
	public SecureId64(QuickUpConfiguration configuration)
	{
		this.configuration = configuration;
	}

	public const int Length = 11;
	private const int PaddedLength = (((Length - 1) / 4) + 1) * 4;

	public string Serialize(long value) => string.Create(Length, value, (span, val) => Serialize(val, span));

	public void Serialize(long value, Span<char> span)
	{
		if (span.Length != Length)
			throw new ArgumentException($"Length must be exactly {Length}.", nameof(span));

		using (var simmeck = new Simeck64(configuration.Simeck64Key))
			value = simmeck.Encrypt(value);

		ToBase64(value, span);
	}

	public long Deserialize(ReadOnlySpan<char> value)
	{
		if (value.Length != Length)
			ThrowInvalidId();

		var data = FromBase64(value);

		using (var simmeck = new Simeck64(configuration.Simeck64Key))
			data = simmeck.Encrypt(data);

		return data;
	}

	private static void ToBase64(long value, Span<char> span)
	{
		Span<byte> data = stackalloc byte[sizeof(long)];
		Span<char> chars = stackalloc char[PaddedLength];

		BitConverter.TryWriteBytes(data, value);

		if (!Convert.TryToBase64Chars(data, chars, out _))
			throw new InvalidOperationException($"Could not convert id to base64: {value}.");

		for (var i = 0; i < Length; i++)
		{
			span[i] = chars[i] switch
			{
				'+' => '-',
				'/' => '_',
				_ => chars[i]
			};
		}
	}

	private static long FromBase64(ReadOnlySpan<char> value)
	{
		Span<char> chars = stackalloc char[PaddedLength];
		Span<byte> bytes = stackalloc byte[sizeof(long)];

		// fill start with decoded incoming chars
		for (var i = 0; i < Length; i++)
		{
			chars[i] = value[i] switch
			{
				'-' => '+',
				'_' => '/',
				_ => value[i]
			};
		}

		// fill remaining chars with padding
		for (int i = Length; i < PaddedLength; i++)
		{
			chars[i] = '=';
		}

		if (!Convert.TryFromBase64Chars(chars, bytes, out var _))
			ThrowInvalidId();

		return BitConverter.ToInt64(bytes);
	}

	[DoesNotReturn]
	static void ThrowInvalidId() => throw new ArgumentException("Invalid id Format");
}
