using Microsoft.EntityFrameworkCore;

using QuickUp.Model;
using QuickUp.Controllers;
using QuickUp;
using QuickUp.Security;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddEnvironmentVariables(prefix: "QUICKUP_");

builder.Services.AddSingleton(c => c.GetRequiredService<IConfiguration>().Get<QuickUpConfiguration>() ?? new());
builder.Services.AddSingleton<SecureId32>();
builder.Services.AddSingleton<SecureId64>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<QuickUpContext>(
	c => c.UseSqlite(builder.Configuration.GetConnectionString("Default"))
);

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
  using var db = scope.ServiceProvider.GetRequiredService<QuickUpContext>();
  db.Database.Migrate();
}

app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();

app.MapControllers();

app.Run();
