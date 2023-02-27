namespace MircoGericke.Cryptography.Simeck.Manipulation;

/// <summary>
/// Contains common span manipulations done in cryptography
/// </summary>
public static class SpanManipulation
{
	/// <summary>
	/// Rotates the values of <paramref name="value"/> one to the left.
	/// </summary>
	public static void RotateRight<T>(Span<T> value)
	{
		if (value.IsEmpty)
			return;

		var temp = value[^1];
		for (var i = value.Length - 1; i >= 1; i--)
		{
			value[i] = value[i - 1];
		}
		value[0] = temp;
	}

	/// <summary>
	/// Rotates the values of <paramref name="value"/> one to the left.
	/// </summary>
	public static void RotateLeft<T>(Span<T> value)
	{
		if (value.IsEmpty)
			return;

		var temp = value[0];
		for (var i = 0; i < value.Length - 1; i++)
		{
			value[i] = value[i + 1];
		}
		value[^1] = temp;
	}
}