using System.Text;
using System.Text.Json;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Data;
using WebApplication1.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AccountsContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("PostGresConnectionString")));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sGQ7+cHIYRyCJoq1l0F9utfBhCG4jxDVq9DKhrWyXys=")),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });

builder.Services.AddControllers();
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization(); //This also applies to minimal apis

app.MapPost("v1/user", async (User user, AccountsContext db) =>
{
    db.Users.Add(user);
    try
    {
        await db.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        return Results.Problem("An error occurred saving the user, please make sure you have entered valid information", "500");
    }
    
    return Results.Created($"/v1/user/{user.Id}", user);
});

app.MapGet("/v1/user/{user_id}", async (int user_id, AccountsContext db) =>
{
    var user = await db.Users.FindAsync(user_id);
    if (user == null) return Results.NotFound(new { message = $"User with id {user_id}, does not exist!" });
    else return Results.Ok(user);
});

app.Run();
