using System.Text;
using Azure.Identity;
using Azure.Messaging.ServiceBus;
using AuthService.BackgroudServices;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

//Lägg till Key Vault
var vaultUri = new Uri(builder.Configuration["KeyVault:Uri"]!);
builder.Configuration.AddAzureKeyVault(vaultUri, new DefaultAzureCredential());

//  Läs secrets
var connString = builder.Configuration.GetConnectionString("DefaultConnection"); 
var jwtKey = builder.Configuration["Jwt:Key"]!;
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;
var jwtExpires = builder.Configuration["Jwt:ExpiresInMinutes"]!;
var adminEmail = builder.Configuration["AdminUser:Email"]!;
var adminPwd = builder.Configuration["AdminUser:Password"]!;
var sbConn = builder.Configuration["ServiceBus:ConnectionString"]!;
var sbQueueName = builder.Configuration["ServiceBus:QueueName"]!;

//  CORS
builder.Services.AddCors(o => o.AddPolicy("DefaultCors", p =>
    p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

//  EF Core
builder.Services.AddDbContext<DataContext>(o =>
    o.UseSqlServer(connString));

//  Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opts => {
    opts.Password.RequiredLength = 6;
    opts.Password.RequireNonAlphanumeric = false;
})
.AddEntityFrameworkStores<DataContext>()
.AddDefaultTokenProviders();

//  Authentication/JWT
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);
builder.Services
  .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
  .AddJwtBearer(opts => {
      opts.RequireHttpsMetadata = true;
      opts.SaveToken = true;
      opts.TokenValidationParameters = new TokenValidationParameters
      {
          ValidateIssuer = true,
          ValidateAudience = true,
          ValidateLifetime = true,
          ValidateIssuerSigningKey = true,
          ValidIssuer = jwtIssuer,
          ValidAudience = jwtAudience,
          IssuerSigningKey = new SymmetricSecurityKey(keyBytes)
      };
  });

builder.Services.AddScoped<ITokenService, TokenService>();

//  Service Bus
builder.Services.AddSingleton(_ => new ServiceBusClient(sbConn));
builder.Services.AddHostedService<EmailConfirmedProcessor>();

//  Controllers + Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c => {
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthService API", Version = "v1" });
    var scheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Skriv: Bearer {token}"
    };
    c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, scheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
    { scheme, Array.Empty<string>() }
  });
});

var app = builder.Build();

// Seed admin
using (var scope = app.Services.CreateScope())
{
    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
    foreach (var role in new[] { "Admin", "User" })
        if (!await roleMgr.RoleExistsAsync(role))
            await roleMgr.CreateAsync(new IdentityRole(role));

    if (await userMgr.FindByEmailAsync(adminEmail) == null)
    {
        var admin = new ApplicationUser { UserName = adminEmail, Email = adminEmail };
        var res = await userMgr.CreateAsync(admin, adminPwd);
        if (res.Succeeded)
            await userMgr.AddToRoleAsync(admin, "Admin");
    }
}

//  Middleware 
app.UseHttpsRedirection();
app.UseCors("DefaultCors");
app.UseAuthentication();
app.UseAuthorization();

app.UseSwagger();
app.UseSwaggerUI(c => {
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService API V1");
    c.RoutePrefix = string.Empty;
});

app.MapControllers();
app.Run();
