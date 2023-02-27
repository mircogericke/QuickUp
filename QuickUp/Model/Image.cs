namespace QuickUp.Model;

public class Image
{
	public int Id { get; set; }
	public string MimeType { get; set; } = "";
	public Guid DeleteKey { get; set; }
	public DateTime CreatedAt { get; set; }
}
