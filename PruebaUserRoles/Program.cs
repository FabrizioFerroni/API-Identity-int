using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using PruebaUserRoles.Data;
using PruebaUserRoles.Models;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using PruebaUserRoles.Services.Interfaces;
using PruebaUserRoles.Services;
using NLog.Web;
using NLog;
using PruebaUserRoles.Configuration;
using Microsoft.Extensions.Options;

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings().GetCurrentClassLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);
    {
        ConfigurationManager configuration = builder.Configuration;

        var services = builder.Services;
        var env = builder.Environment;

        // Add services to the container.

        // For Entity Framework
        services.AddDbContext<ApplicationContext>(options => options.UseSqlServer(configuration.GetConnectionString("WebApiDatabase")));

        services.Configure<MailSettings>(configuration.GetSection(nameof(MailSettings)));

        // For Identity
        services.AddIdentity<User, Role>(config =>
        {
            config.User.RequireUniqueEmail = true;
            config.Tokens.AuthenticatorIssuer = "JWT";
            config.SignIn.RequireConfirmedEmail = true;
            config.SignIn.RequireConfirmedAccount = true;

            config.Password.RequiredLength = 8;
            config.Password.RequiredUniqueChars = 3;
            config.Password.RequireNonAlphanumeric = true;
            config.Password.RequireUppercase = true;
            config.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._";

            config.Lockout.AllowedForNewUsers = true;
            config.Lockout.MaxFailedAccessAttempts = 3;
            config.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
        })
            .AddEntityFrameworkStores<ApplicationContext>()
            .AddDefaultTokenProviders();

        services.Configure<DataProtectionTokenProviderOptions>(opt =>
                        opt.TokenLifespan = TimeSpan.FromHours(2)
                        );

        // Adding Authentication
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })

        // Adding Jwt Bearer
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = configuration["JWT:ValidAudience"],
                ValidIssuer = configuration["JWT:ValidIssuer"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]))
            };
        });

        //services.AddScoped<IUsuarioService, UsuarioService>();
        services.AddScoped<IEmailService, EmailService>();

        //services.AddControllers();
        services.AddControllers().AddJsonOptions(x =>
        {
            // serialize enums as strings in api responses (e.g. Role)
            x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
            x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;

        });
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(c =>
        {
            c.OperationFilter<SecurityRequirementsOperationFilter>();

            c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
            {
                Description = "Autorizacion Standar, Usar Bearer. Ejemplo \"bearer {token}\"",
                In = ParameterLocation.Header,
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });

        });

        // configure strongly typed settings object
        services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));

        builder.Logging.ClearProviders();
        builder.Host.UseNLog();
    }

    var app = builder.Build();

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        
    }

    app.UseSwagger();
    app.UseSwaggerUI(x => x.SwaggerEndpoint("/swagger/v1/swagger.json", "API Test identity int"));

    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Se detuvo el programa porque hay una excepcion");
    throw;
}
finally
{
    NLog.LogManager.Shutdown();
}
