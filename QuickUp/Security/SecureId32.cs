namespace QuickUp.Security;

using System.Diagnostics.CodeAnalysis;

using MircoGericke.Cryptography.Simeck;

public class SecureId32
{
	private readonly QuickUpConfiguration configuration;
	public SecureId32(QuickUpConfiguration configuration)
	{
		this.configuration = configuration;
	}

	public const int Length = 6;
	private const int PaddedLength = (((Length - 1) / 4) + 1) * 4;

	public string Serialize(int value) => string.Create(Length, value, (span, val) => Serialize(val, span));

	public void Serialize(int value, Span<char> span)
	{
		if (span.Length != Length)
			throw new ArgumentException($"Length must be exactly {Length}.", nameof(span));

		using (var simmeck = new Simeck32(configuration.Simeck32Key))
			value = simmeck.Encrypt(value);

		ToBase64(value, span);
	}

	public int Deserialize(ReadOnlySpan<char> value)
	{
		if (value.Length != Length)
			ThrowInvalidId();

		var data = FromBase64(value);

		using (var simmeck = new Simeck32(configuration.Simeck32Key))
			data = simmeck.Decrypt(data);

		return data;
	}

	private static void ToBase64(int value, Span<char> span)
	{
		Span<byte> data = stackalloc byte[sizeof(int)];
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

	private static int FromBase64(ReadOnlySpan<char> value)
	{
		Span<char> chars = stackalloc char[PaddedLength];
		Span<byte> bytes = stackalloc byte[sizeof(int)];

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

		if (!Convert.TryFromBase64Chars(chars, bytes, out int _))
			ThrowInvalidId();

		return BitConverter.ToInt32(bytes);
	}

	[DoesNotReturn]
	static void ThrowInvalidId() => throw new ArgumentException("Invalid id Format");
}
