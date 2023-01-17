using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PruebaUserRoles.Data;
using PruebaUserRoles.Models.Role;
using PruebaUserRoles.Models.User;
using System.Configuration;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

{
    var services = builder.Services;
    var env = builder.Environment;
    // Add services to the container.

    services.AddDbContext<ApplicationContext>(options =>
                               options.UseSqlServer(builder.Configuration.GetConnectionString("WebApiDatabase")));
    services.AddIdentity<User, Role>()
          .AddEntityFrameworkStores<ApplicationContext>()
          .AddDefaultTokenProviders();

    services.AddCors();
    services.AddControllers().AddJsonOptions(x =>
    {
        // serialize enums as strings in api responses (e.g. Role)
        x.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
    //services.AddControllers();
    // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
    services.AddEndpointsApiExplorer();
    services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());

    services.AddSwaggerGen();

    // configure strongly typed settings object
    services.Configure<AppSettings>(builder.Configuration.GetSection("AppSettings"));
}

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dataContext = scope.ServiceProvider.GetRequiredService<ApplicationContext>();
    dataContext.Database.Migrate();
}

// Configure the HTTP request pipeline.
{
    if (app.Environment.IsDevelopment())
    {
    }


    app.UseSwagger();
    app.UseSwaggerUI(x => x.SwaggerEndpoint("/swagger/v1/swagger.json", "API Test identity int"));


    app.UseCors(x => x
      .SetIsOriginAllowed(origin => true)
      .AllowAnyMethod()
      .AllowAnyHeader()
      .AllowCredentials());

    // global error handler
    app.UseMiddleware<ErrorHandlerMiddleware>();


    app.UseHttpsRedirection();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();
}
app.Run();
