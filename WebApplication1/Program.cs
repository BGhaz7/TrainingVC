using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
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
using RabbitMQ.Client;

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
    private static string GenerateJwtToken(string username, List<Claim> claims)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("sGQ7+cHIYRyCJoq1l0F9utfBhCG4jxDVq9DKhrWyXys="));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        //Issuer and Audience?
        var token = new JwtSecurityToken(
            issuer: null, 
            audience: null, 
            claims: claims,
            expires: DateTime.Now.AddHours(1), // Token expiration time
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
    
    private static string extractToken(HttpContext context)
    {
        var authorizationHeader = context.Request.Headers["Authorization"].ToString();
        if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Missing or invalid Authorization header.");
        }
        return authorizationHeader["Bearer ".Length..].Trim();
    }
    
    private static int extractIdFromJWT(string token)
    {
        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);
        var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier);
        if (userIdClaim == null)
        {
            throw new InvalidOperationException("Token does not contain a user ID.");
        }
        return int.Parse(userIdClaim.Value);
    }
    public static void Main(string[] args)
    {
        var accountSender = new ConnectionFactory { HostName = "localhost", Port = 5157};
        using var connection = accountSender.CreateConnection();
        using var channel = connection.CreateModel();
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
                
                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                        {
                            context.Response.Headers.Append("Token-Expired", "true");
                        }

                        if (context.Exception.GetType() == typeof(SecurityTokenInvalidSignatureException))
                        {
                            context.Response.Headers.Append("Token-Invalid", "true");
                        }
                        return Task.CompletedTask;
                    }
                };
                    
                options.Events = new JwtBearerEvents
                {
                    OnChallenge = context =>
                    {
                        context.HandleResponse();
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        context.Response.ContentType = "application/json";
                        return context.Response.WriteAsync(JsonSerializer.Serialize(new { error = "You are not authorized or your token has expired." }));
                    }
                };
            });

        builder.Services.AddControllers();
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization(); //This also applies to minimal apis
        app.Use(async (context, next) =>
        {
            await next();

            if (context.Response is { StatusCode: 401, HasStarted: false })
            {
                // Handle the case where the token is invalid or expired
                // Modify the response if needed
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = "Invalid or expired token provided." }));
            }
        });


        app.MapPost("v1/user", async (HttpContext httpContext,UserRegisterDto userDto, AccountsContext db) =>
        {
            channel.QueueDeclare(queue: "recordCreate",
                durable: false,
                exclusive: false,
                autoDelete: false,
                arguments: null);
            var user = new User
            {
                username = userDto.username,
                email = userDto.email,
                SHA256Password = pwHasher.hashPw(userDto.password),
                fname = userDto.fname,
                lname = userDto.lname,
                loggedin = false
            };
            db.Users.Add(user);
            try
            {
                await db.SaveChangesAsync();
                var message = JsonSerializer.Serialize(new
                {
                    UserId = user.Id,
                    FirstName = user.fname,
                    Email = user.email
                });
                var body = Encoding.UTF8.GetBytes(message);
                channel.BasicPublish(exchange: String.Empty,
                    routingKey: "recordCreate",
                    basicProperties: null,
                    body: body);
                Console.WriteLine(" [x] Sent {0}", message);
                /*using (var client = new HttpClient())
                {
                    var claims = new List<Claim>
                    {
                        new(JwtRegisteredClaimNames.Name, user.fname),
                        new(JwtRegisteredClaimNames.Email, user.email),
                        new(JwtRegisteredClaimNames.NameId, user.Id.ToString())
                    };
                    var token = GenerateJwtToken(user.username, claims);
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    var response = await client.PostAsync("http://localhost:5157/v1/createRecord", null);
                    Console.WriteLine(response);
                    if (response.IsSuccessStatusCode)
                    {
                        var responseContent = await response.Content.ReadAsStringAsync();
                        Console.WriteLine(responseContent);
                    }
                    else
                    {
                        Console.WriteLine("Error calling API");
                    }
                }*/
                

            }
            catch (DbUpdateException)
            {
                return Results.Problem(
                    "An error occurred saving the user, please make sure you have entered valid information", "500");
            }

            return Results.Created($"/v1/user/{user.Id}", user);
        });

        app.MapGet("/v1/user/{user_id}", async (HttpContext httpContext, int user_id, AccountsContext db) =>
        {
            var user = await db.Users.FindAsync(user_id);
            if (user == null) return Results.NotFound(new { message = $"User with id {user_id}, does not exist!" });
            if (user.loggedin != true) return Results.NotFound(new {message = $"User with id {user_id} is not logged in!" });
            try
            {
                await db.SaveChangesAsync();
                var claims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.NameId, user.Id.ToString())
                };
                using (var client = new HttpClient())
                {
                    var token = extractToken(httpContext);
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    var transactionResponse = await client.GetAsync("http://localhost:5157/v1/transactions");
                    var balanceResponse = await client.GetAsync("http://localhost:5157/v1/balance");
                    Console.WriteLine(transactionResponse);
                    Console.WriteLine(balanceResponse);
                    if (transactionResponse.StatusCode == HttpStatusCode.OK && balanceResponse.StatusCode == HttpStatusCode.OK)
                    {
                        var tresponseContent = await transactionResponse.Content.ReadAsStringAsync();
                        var bresponseContent = await balanceResponse.Content.ReadAsStringAsync();
                        Console.WriteLine(tresponseContent);
                        Console.WriteLine(bresponseContent);
                    }
                    else
                    {
                        Console.WriteLine(transactionResponse);
                        Console.WriteLine(balanceResponse);
                        Console.WriteLine("Error calling Payment Services API");
                    }
                }

            }
            catch (DbUpdateException)
            {
                return Results.Problem(
                    "An error occurred saving the user, please make sure you have entered valid information", "500");
            }

            return Results.Ok(user);
        });

        app.MapPost("v1/login", async (UserLoginDto UserLoginReq, AccountsContext db) =>
        {
            var user = await db.Users
                .FirstOrDefaultAsync(u =>
                    u.username == UserLoginReq.username);
                if (user == null)
                {
                    return Results.BadRequest("Invalid Username or Password");
                }
            else if (pwHasher.VerifyHashedPw(user.SHA256Password, UserLoginReq.password) == true)
            {


                var claims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Name, user.fname),
                    new(JwtRegisteredClaimNames.Email, user.email),
                    new(JwtRegisteredClaimNames.NameId, user.Id.ToString())
                };
                user.loggedin = true;
                Console.WriteLine(user.loggedin);
                await db.SaveChangesAsync();
                var token = GenerateJwtToken(user.username, claims);
                return Results.Ok(new { token });

            }
            return Results.BadRequest("Invalid Username or Password");
        }
    );

        app.MapPut("v1/user/{user_id}", async (HttpContext httpContext ,int user_id, UserRegisterDto modified,AccountsContext db) =>
        {
            var user = await db.Users.FindAsync(user_id);
            if (user == null || user.loggedin != true)
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
