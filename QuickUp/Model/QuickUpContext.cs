namespace QuickUp.Model;

using Microsoft.EntityFrameworkCore;

public class QuickUpContext : DbContext
{
	public DbSet<Image> Image { get; set; }

	public QuickUpContext(DbContextOptions<QuickUpContext> options)
		: base(options) { }
}
