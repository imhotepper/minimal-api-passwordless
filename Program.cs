
//https://www.freecodecamp.org/news/how-to-go-passwordless-with-dotnet-identity/
//based on this one: https://www.scottbrady91.com/aspnet-identity/implementing-mediums-passwordless-authentication-using-aspnet-core-identity

using System.Text;
using System.Web;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{   
    options.DefaultScheme = IdentityConstants.ExternalScheme;
});

//identity
builder.Services.AddIdentityCore<IdentityUser>(o =>
    {
        o.SignIn.RequireConfirmedEmail = false;
        o.SignIn.RequireConfirmedAccount = false;
        o.SignIn.RequireConfirmedPhoneNumber = false;
    })
                .AddEntityFrameworkStores<AppDb>()
                .AddDefaultTokenProviders();
                 //.AddTokenProvider<TotpSecurityStampBasedTokenProvider<IdentityUser>>(TokenOptions.DefaultEmailProvider);
               //;


builder.Services.AddDbContext<AppDb>(options =>
    options.UseInMemoryDatabase(Guid.NewGuid().ToString()),
    ServiceLifetime.Singleton);




var app = builder.Build();



app.MapGet("/", () => "Hello World!");

app.MapGet("/api/{email}",async (string email, UserManager<IdentityUser> _userManager, HttpRequest req) =>{
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
    // req.HttpContext.Request;
    token = HttpUtility.UrlEncode(token);
Console.WriteLine($"{req.Scheme}://{req.Host}/api/verify?email={email}&token={token}");

// var IsValid = await _userManager.
//     VerifyUserTokenAsync(User, TokenOptions.DefaultProvider, "passwordless",HttpUtility.UrlDecode(token));
// Console.WriteLine("Validation :"+ IsValid);
    // DON'T RETURN THE TOKEN.
    // SEND IT TO THE USER VIA EMAIL.
    
    
    return Results.NoContent();
});


app.MapGet("/api/verify",async ( string email, string token, UserManager<IdentityUser> _userManager) =>{
    Console.WriteLine($"Received email: {email} and token:{token}");

 // Fetch your user from the database
    var User = await _userManager.FindByNameAsync(email);
   
    if (User == null)
    {
        return Results.NotFound();
    }
 Console.WriteLine($"Verify user found: {User.Email}");

    var IsValid = await _userManager.
        VerifyUserTokenAsync(User, TokenOptions.DefaultProvider, "passwordless",token.Trim());
    if (IsValid)
    {
        // TODO: Generate a bearer token
        var BearerToken = "aaaaaabbbbbb";
        Console.WriteLine("All good returning  bearer:" + BearerToken);
        return Results.Ok( BearerToken);
    }
    return Results.Unauthorized();


});


app.Run();



public class AppDb: IdentityDbContext{
    public AppDb(DbContextOptions<AppDb> options): base(options)
    {
        
    }
}