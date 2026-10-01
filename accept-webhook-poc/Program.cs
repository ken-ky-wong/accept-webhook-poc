using System.IO;
using Azure.Identity;
using accept_webhook_poc.Services;
using Serilog;
using Serilog.Context;
using Serilog.Events;
using System.Security.Authentication;

var builder = WebApplication.CreateBuilder(args);

var logFilePath = builder.Configuration["Serilog:FilePath"];
if (string.IsNullOrWhiteSpace(logFilePath))
{
    var appServiceHome = Environment.GetEnvironmentVariable("HOME");
    var appServiceInstanceId = Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID");
    logFilePath = !string.IsNullOrWhiteSpace(appServiceHome) &&
                  !string.IsNullOrWhiteSpace(appServiceInstanceId)
        ? Path.Combine(
            appServiceHome,
            "LogFiles",
            "Application",
            Path.GetFileName(appServiceInstanceId),
            "webhook-.log")
        : Path.Combine(builder.Environment.ContentRootPath, "logs", "webhook-.log");
}

if (!Path.IsPathRooted(logFilePath))
{
    logFilePath = Path.GetFullPath(logFilePath, builder.Environment.ContentRootPath);
}

var logDirectory = Path.GetDirectoryName(logFilePath)
    ?? throw new InvalidOperationException("The configured log file path has no directory.");
Directory.CreateDirectory(logDirectory);

var outputTemplate = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] TraceIdentifier={TraceIdentifier} {Message:lj}{NewLine}{Exception}";
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
    .WriteTo.Console(outputTemplate: outputTemplate)
    .WriteTo.File(
        logFilePath,
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 14,
        fileSizeLimitBytes: 10 * 1024 * 1024,
        rollOnFileSizeLimit: true,
        outputTemplate: outputTemplate)
    .CreateBootstrapLogger();

try
{
    builder.Host.UseSerilog((context, services, loggerConfiguration) =>
        loggerConfiguration
            .ReadFrom.Configuration(context.Configuration)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate: outputTemplate)
            .WriteTo.File(
                logFilePath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                fileSizeLimitBytes: 10 * 1024 * 1024,
                rollOnFileSizeLimit: true,
                outputTemplate: outputTemplate));

    var keyVaultUri = builder.Configuration["KeyVault:Uri"];
    if (!string.IsNullOrWhiteSpace(keyVaultUri))
    {
        builder.Configuration.AddAzureKeyVault(
            new Uri(keyVaultUri),
            new DefaultAzureCredential());
        Log.Information("Azure Key Vault configuration is enabled");
    }

    builder.Services.AddControllers();
    builder.Services.AddSwaggerGen(options =>
        options.OperationFilter<accept_webhook_poc.Swagger.AuthorizeNetWebhookOperationFilter>());
    builder.Services.AddHttpClient<IAcceptHostedSessionService, AuthorizeNetAcceptHostedSessionService>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        SslProtocols = SslProtocols.Tls12
    });    
    builder.Services.AddSingleton<IAuthorizeNetWebhookStore, InMemoryAuthorizeNetWebhookStore>();
    builder.Services.AddSingleton<AuthorizeNetWebhookSignatureValidator>();

    var app = builder.Build();

    app.Use(async (context, next) =>
    {
        using (LogContext.PushProperty("TraceIdentifier", context.TraceIdentifier))
        {
            await next();
        }
    });

    app.UseSerilogRequestLogging(options =>
    {
        options.GetLevel = (context, _, exception) =>
            exception is not null || context.Response.StatusCode >= StatusCodes.Status500InternalServerError
                ? LogEventLevel.Error
                : context.Response.StatusCode >= StatusCodes.Status400BadRequest
                    ? LogEventLevel.Warning
                    : LogEventLevel.Information;
    });

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception exception)
{
    Log.Fatal(exception, "Application terminated unexpectedly");
    throw;
}
finally
{
    Log.CloseAndFlush();
}
