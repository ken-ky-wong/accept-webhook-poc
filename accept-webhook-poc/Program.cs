using Azure.Identity;
using accept_webhook_poc.Services;

var builder = WebApplication.CreateBuilder(args);

var keyVaultUri = builder.Configuration["KeyVault:Uri"];
if (!string.IsNullOrWhiteSpace(keyVaultUri))
{
    builder.Configuration.AddAzureKeyVault(
        new Uri(keyVaultUri),
        new DefaultAzureCredential());
}

// Add services to the container.

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddSingleton<IAuthorizeNetWebhookStore, InMemoryAuthorizeNetWebhookStore>();
builder.Services.AddSingleton<AuthorizeNetWebhookSignatureValidator>();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api/webhooks/authorize-net"))
    {
        context.Request.EnableBuffering();
    }

    await next();
});

app.UseAuthorization();

app.MapControllers();

app.Run();
