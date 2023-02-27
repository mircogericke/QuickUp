namespace QuickUp.Controllers;

using System.Net.Http.Headers;
using System.Text.Json.Nodes;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;

using QuickUp.Model;
using QuickUp.Security;

[Route("/")]
[ApiController]
public class ImageController : ControllerBase
{
	private readonly QuickUpConfiguration configuration;
	private readonly SecureId32 secureId;
	private readonly QuickUpContext db;

	public ImageController(
		QuickUpConfiguration configuration,
		SecureId32 secureId,
		QuickUpContext db
	)
	{
		this.configuration = configuration;
		this.secureId = secureId;
		this.db = db;
	}

	[HttpPost, Route("/")]
	[ProducesResponseType(StatusCodes.Status201Created)]
	public async Task<IActionResult> UploadAsync([FromHeader(Name = "Authorization")] string authentication)
	{
		try
		{
			var auth = AuthenticationHeaderValue.Parse(authentication);
			if (
				!"Bearer".Equals(auth.Scheme, StringComparison.OrdinalIgnoreCase) ||
				!configuration.UploadSecret.Equals(auth.Parameter, StringComparison.Ordinal)
			)
			{
				return Unauthorized();
			}

			var data = new Image()
			{
				CreatedAt = DateTime.UtcNow,
				DeleteKey = Guid.NewGuid(),
				MimeType = Request.ContentType ?? "image/*"
			};

			db.Image.Add(data);
			await db.SaveChangesAsync(HttpContext.RequestAborted);

			var id = secureId.Serialize(data.Id);

			var result = new Dictionary<string, string>()
			{
				["id"] = id,
				["deleteKey"] = data.DeleteKey.ToString(),
			};

			var path = ToFilePath(id);

			Directory.CreateDirectory(Path.GetDirectoryName(path)!);
			await using(var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
			{
				await Request.BodyReader.CopyToAsync(file);
			}

			return new JsonResult(result) { StatusCode = StatusCodes.Status201Created };
		}
		catch (FormatException)
		{
			return Unauthorized();
		}
	}

	[HttpDelete, Route("{id}")]
	public async Task<IActionResult> DeleteAsync([FromRoute(Name = "id")] string encodedId, [FromQuery] Guid deleteKey)
	{
		var id = secureId.Deserialize(encodedId);

		var query = db.Image.Where(v => v.Id == id);
		var img = await query.FirstOrDefaultAsync(HttpContext.RequestAborted);

		if (img == null)
			return NotFound();

		if (img.DeleteKey != deleteKey)
			return Forbid();

		System.IO.File.Delete(ToFilePath(encodedId));

		await query.ExecuteDeleteAsync();

		return Ok();
	}

	[HttpGet, Route("{id}")]
	public async Task<IActionResult> GetAsync([FromRoute(Name = "id")] string encodedId)
	{
		var id = secureId.Deserialize(encodedId);
		var img = await db.Image.Where(v => v.Id == id).FirstOrDefaultAsync(HttpContext.RequestAborted);

		if (img is null)
			return NotFound();

		var path = ToFilePath(encodedId);

		return PhysicalFile(path, img.MimeType);
	}

	private static string ToFilePath(string id)
	{
		const string DataDirectory = "/data/img";

		var parts = id
			.ToCharArray()
			.Select(v => v.ToString())
			.ToArray();

		var path = Path.GetFullPath(Path.Join(parts), DataDirectory);
		var relative = Path.GetRelativePath(DataDirectory, path);

		if (
			relative == ".." ||
			relative.StartsWith("../", StringComparison.Ordinal) ||
			Path.IsPathRooted(relative)
		)
		{
			throw new ArgumentOutOfRangeException(nameof(id), $"Attempt to escape data directory using id '{id}'.");
		}

		return path;
	}

}
