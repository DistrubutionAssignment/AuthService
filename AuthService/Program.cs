using System.Text;
using AuthService.BackgroudServices;
using AuthService.Data;
using AuthService.Models;
using AuthService.Services;
using Azure.Messaging.ServiceBus;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultCors", policy =>
            policy.AllowAnyOrigin()
            .AllowAnyHeader()
            .AllowAnyMethod());
});

builder.Services.AddDbContext<DataContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
})
    .AddEntityFrameworkStores<DataContext>()
    .AddDefaultTokenProviders();

var jwtSection = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSection["Key"]!);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSection["Issuer"],
            ValidAudience = jwtSection["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });


builder.Services.AddScoped<ITokenService, TokenService>();

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "EventService API", Version = "v1" });

    var securityScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Skriv: Bearer {token}"
    };
    c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, securityScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
      { securityScheme, Array.Empty<string>() }
    });
});

builder.Services.AddSingleton(sp =>
{
    var sbConn = builder.Configuration["ServiceBus:ConnectionString"];
    return new ServiceBusClient(sbConn);
});
builder.Services.AddHostedService<EmailConfirmedProcessor>();

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var roleMgr = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userMgr = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

    foreach (var role in new[] { "Admin", "User" })
    {
        if (!await roleMgr.RoleExistsAsync(role))
        {
            await roleMgr.CreateAsync(new IdentityRole(role));
        }
    }

    var adminEmail = builder.Configuration["AdminUser:Email"]!;
    var adminPassword = builder.Configuration["AdminUser:Password"]!;
    if (await userMgr.FindByEmailAsync(adminEmail) == null)
    {
        var admin = new ApplicationUser{UserName = adminEmail,Email = adminEmail,};
        var res = await userMgr.CreateAsync(admin, adminPassword);
        if (res.Succeeded)
            await userMgr.AddToRoleAsync(admin, "Admin");
    }
}

app.UseHttpsRedirection();
app.UseCors("DefaultCors");
app.UseAuthentication();
app.UseAuthorization();
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "AuthService API V1");
    c.RoutePrefix = string.Empty;
});
app.MapOpenApi();
app.MapControllers();
app.Run();
