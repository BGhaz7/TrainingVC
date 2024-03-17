using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.IdentityModel.Tokens;
using WebApplication1.Data;
using WebApplication1.Models;
public class pwHasher
{
    public static string hashPw(string pw)
    {
        //Randomization of the salt variable BEFORE hashing
        byte[] salt = new byte[128 / 8];
        using (var rngCsp = RandomNumberGenerator.Create())
        {
            rngCsp.GetNonZeroBytes(salt);
        }
        string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: pw,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        // Return the salt and the hash
        return $"{Convert.ToBase64String(salt)}:{hashed}";
    
        
    }
    
    public bool VerifyHashedPw(string hashedPwWithSalt, string pw)
    {
        var parts = hashedPwWithSalt.Split(':', 2);

        if (parts.Length != 2)
        {
            throw new FormatException("The stored password is not in the expected format.");
        }

        var salt = Convert.FromBase64String(parts[0]);
        var hashed = Convert.FromBase64String(parts[1]);

        // Derive the hash from the given password and salt
        string verificationHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: pw,
            salt: salt,
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        return hashed.SequenceEqual(Convert.FromBase64String(verificationHash));
    }
}



internal class Program
{
    private static string GenerateJwtToken(string username, Claim[] claims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sGQ7+cHIYRyCJoq1l0F9utfBhCG4jxDVq9DKhrWyXys="));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: null, 
            audience: null, 
            claims: claims,
            expires: DateTime.Now.AddHours(1), // Token expiration time
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    public static void Main(string[] args)
    {
        var pwHasher = new pwHasher();
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddDbContext<AccountsContext>(options =>
            options.UseNpgsql(builder.Configuration.GetConnectionString("PostGresConnectionString")));
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey =
                        new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes("sGQ7+cHIYRyCJoq1l0F9utfBhCG4jxDVq9DKhrWyXys=")),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });

        builder.Services.AddControllers();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization(); //This also applies to minimal apis


        app.MapPost("v1/user", async (UserRegisterDto userDto, AccountsContext db) =>
        {
            var user = new User
            {
                username = userDto.username,
                email = userDto.email,
                SHA256Password = pwHasher.hashPw(userDto.password),
                fname = userDto.fname,
                lname = userDto.lname
            };
            db.Users.Add(user);
            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                return Results.Problem(
                    "An error occurred saving the user, please make sure you have entered valid information", "500");
            }

            return Results.Created($"/v1/user/{user.Id}", user);
        });

        app.MapGet("/v1/user/{user_id}", async (int user_id, AccountsContext db) =>
        {
            var user = await db.Users.FindAsync(user_id);
            if (user == null) return Results.NotFound(new { message = $"User with id {user_id}, does not exist!" });
            else return Results.Ok(user);
        });

        app.MapPost("v1/login", async (UserLoginDto UserLoginReq, AccountsContext db) =>
        {
            var user = await db.Users
                .AsNoTracking()
                .FirstOrDefaultAsync(u =>
                    u.username == UserLoginReq.username);
            if (user == null)
            {
                return Results.BadRequest("Invalid Username or Password");
            }
            else if (pwHasher.VerifyHashedPw(user.SHA256Password, UserLoginReq.password) == true)
            {


                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.username)
                };

                var token = GenerateJwtToken(user.username, claims);
                return Results.Ok(new { token });

            }
            return Results.BadRequest("Invalid Username or Password");
        }
    );

        app.MapPut("v1/user/{user_id}", async (int user_id, UserRegisterDto modified ,AccountsContext db) =>
        {
            var user = await db.Users.FindAsync(user_id);
            if (user == null)
            {
                Results.BadRequest("No such user found!");
            }

            user.username = modified.username;
            user.email = modified.email;
            user.fname = modified.fname;
            user.lname = modified.lname;
            user.SHA256Password = pwHasher.hashPw(modified.password);

            await db.SaveChangesAsync();
            return Results.NoContent();
        });

    app.Run();
    }
}
