namespace QuickUp;

using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

using MircoGericke.Cryptography.Simeck.Manipulation;

public class QuickUpConfiguration
{
	private string applicationSecret = "";
	private ulong simeck32;
	private UInt128 simeck64;

	public string ApplicationSecret
	{
		get => applicationSecret;
		set
		{
			applicationSecret= value;
			DerriveKeys(value);
		}
	}

	public string UploadSecret { get; set; } = "";

	public ulong Simeck32Key => simeck32;
	public UInt128 Simeck64Key => simeck64;

	private void DerriveKeys(string secretString)
	{
		var secretBytes = Convert.FromHexString(secretString);
		var password = secretBytes.AsSpan()[0..^8];
		var salt = secretBytes.AsSpan()[^8..];

		Span<byte> destination = stackalloc byte[Unsafe.SizeOf<UInt128>() + sizeof(ulong)];

		Rfc2898DeriveBytes.Pbkdf2(password, salt, destination, 50000, HashAlgorithmName.SHA512);

		simeck32 = BinaryPrimitives.ReadUInt64LittleEndian(destination[^sizeof(ulong)..]);
		simeck64 = BinaryPrimitivesEx.ReadUInt128LittleEndian(destination);
	}
}
