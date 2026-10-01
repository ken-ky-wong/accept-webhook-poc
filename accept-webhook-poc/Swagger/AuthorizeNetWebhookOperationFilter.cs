using accept_webhook_poc.Controllers;
using accept_webhook_poc.Models;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace accept_webhook_poc.Swagger;

public sealed class AuthorizeNetWebhookOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (context.MethodInfo.DeclaringType != typeof(AuthorizeNetWebhookController)
            || context.MethodInfo.Name != nameof(AuthorizeNetWebhookController.Receive))
        {
            return;
        }

        operation.RequestBody = new OpenApiRequestBody
        {
            Required = true,
            Content = new Dictionary<string, OpenApiMediaType>
            {
                ["application/json"] = new OpenApiMediaType
                {
                    Schema = context.SchemaGenerator.GenerateSchema(
                        typeof(AuthorizeNetWebhookNotification),
                        context.SchemaRepository)
                }
            }
        };
    }
}