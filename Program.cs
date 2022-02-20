//Resources used
//https://www.freecodecamp.org/news/how-to-go-passwordless-with-dotnet-identity/
//https://www.scottbrady91.com/aspnet-identity/implementing-mediums-passwordless-authentication-using-aspnet-core-identity

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using SendGrid;
using SendGrid.Helpers.Mail;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = builder.Environment.ApplicationName, Version = "v1" });

    #region Bearer

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT authorization using bearer scheme",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Header,
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    #endregion
});


builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddAuthorization();

//identity
builder.Services.AddIdentityCore<IdentityUser>(o =>
    {
        o.SignIn.RequireConfirmedEmail = false;
        o.SignIn.RequireConfirmedAccount = false;
        o.SignIn.RequireConfirmedPhoneNumber = false;
    })
    .AddEntityFrameworkStores<AppDb>()
    .AddDefaultTokenProviders();

builder.Services.AddDbContext<AppDb>(options =>
        options.UseInMemoryDatabase(Guid.NewGuid().ToString()),
    ServiceLifetime.Singleton);

builder.Services.AddScoped<SendGridService>()
    .AddScoped<TokenService>();

var app = builder.Build();

//swagger initialization
app.UseSwagger();
app.UseSwaggerUI(c => { c.SwaggerEndpoint("/swagger/v1/swagger.json", $"{builder.Environment.ApplicationName} v1"); });

//Add authentication
app.UseAuthentication();
app.UseAuthorization();


app.MapGet("/", () => "UnAuthenticated Hello World !");

app.MapGet("/api/{email}",
    async (string email, UserManager<IdentityUser> _userManager, HttpRequest req, SendGridService sendGridService) =>
    {
        // Create or Fetch your user from the database
        var User = await _userManager.FindByNameAsync(email);
        if (User == null)
        {
            User = new IdentityUser();
            User.Email = email;
            User.UserName = email;
            var IdentityResult = await _userManager.CreateAsync(User);
            if (IdentityResult.Succeeded == false)
            {
                return Results.BadRequest();
            }
        }

        var token = await _userManager.GenerateUserTokenAsync(User,
            TokenOptions.DefaultProvider, "passwordless");

        var pathurl = req.Host;
        token = HttpUtility.UrlEncode(token);
        var url = $"{req.Scheme}://{req.Host}/api/verify?email={email}&token={token}";
        Console.WriteLine(url);

        await sendGridService.SendEmail(email, url);

        return Results.Text("An email was sent to the address provided. Check for the authentication link inside it.");
    });


app.MapGet("/api/verify",
    async (string email, string token, UserManager<IdentityUser> _userManager, TokenService tokenService) =>
    {
        Console.WriteLine($"Received email: {email} and token:{token}");

        // Fetch your user from the database
        var user = await _userManager.FindByNameAsync(email);

        if (user == null)
            return Results.NotFound();

        Console.WriteLine($"Verify user found: {user.Email}");

        var isValid =
            await _userManager.VerifyUserTokenAsync(user, TokenOptions.DefaultProvider, "passwordless", token.Trim());
        if (isValid)
        {
            // TODO: Generate a bearer token
            var bearerToken = tokenService.GetToken(user);
            Console.WriteLine("All good returning  bearer:" + bearerToken);
            return Results.Text(bearerToken);
        }

        return Results.Unauthorized();
    });

app.MapGet("/api/dashboard", (ClaimsPrincipal user) => Results.Ok($"{user.Identity?.Name} is Authenticated! "))
    .RequireAuthorization();

app.Run();


public class AppDb : IdentityDbContext
{
    public AppDb(DbContextOptions<AppDb> options) : base(options)
    {
    }
}


public class SendGridService
{
    private readonly IConfiguration _configuration;

    public SendGridService(IConfiguration configuration) => _configuration = configuration;

    public async Task SendEmail(string email, string url)
    {
        var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY") ?? _configuration["SENDGRID_API_KEY"];
        var fromEmail = Environment.GetEnvironmentVariable("FROM_EMAIL") ?? _configuration["FROM_EMAIL"];
        var client = new SendGridClient(apiKey);
        var from = new EmailAddress(fromEmail, "Passwordless login");
        var subject = "Passwordless login link";
        var to = new EmailAddress(email);
        var htmlContent = $"<h2>Click the link below to login to passwwordless</h2><br/><h3> <a href=" + url +
                          "> Login</a></h3>";
        var msg = MailHelper.CreateSingleEmail(from, to, subject, "", htmlContent);
        var response = await client.SendEmailAsync(msg);
        Console.WriteLine("Sendgrid response:" + JsonConvert.SerializeObject(response));
    }
}


public class TokenService
{
    private readonly IConfiguration _configuration;

    public TokenService(IConfiguration configuration) => _configuration = configuration;

    public string GetToken(IdentityUser user)
    {
        var validIssuer = _configuration["Jwt:Issuer"];
        var validAudience = _configuration["Jwt:Audience"];
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        var tokenClaims = new JwtSecurityToken(claims: new[]
            {
                new Claim("name", user.Email),
                new Claim("sub", user.Id.ToString())
            }, issuer: validIssuer, audience: validAudience,
            signingCredentials: credentials);
        var token = new JwtSecurityTokenHandler().WriteToken(tokenClaims);
        return token;
    }
}