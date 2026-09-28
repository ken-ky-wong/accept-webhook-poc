using System.Text;
using accept_webhook_poc.Models;
using accept_webhook_poc.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace accept_webhook_poc.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/webhooks/authorize-net")]
public sealed class AuthorizeNetWebhookController(
    IAuthorizeNetWebhookStore webhookStore,
    AuthorizeNetWebhookSignatureValidator signatureValidator) : ControllerBase
{
    /// <summary>
    /// Receives a signed Authorize.Net webhook and stores its unmodified JSON in memory.
    /// </summary>
    [HttpPost]
    [Consumes("application/json")]
    [ProducesResponseType(typeof(AuthorizeNetWebhookReceipt), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status503ServiceUnavailable)]
    public async Task<ActionResult<AuthorizeNetWebhookReceipt>> Receive(
        [FromBody] AuthorizeNetWebhookNotification notification,
        [FromHeader(Name = "X-ANET-Signature")] string? signature,
        CancellationToken cancellationToken)
    {
        Request.Body.Position = 0;

        await using var bodyBuffer = new MemoryStream();
        await Request.Body.CopyToAsync(bodyBuffer, cancellationToken);
        var rawBody = bodyBuffer.ToArray();

        var validationResult = signatureValidator.Validate(
            rawBody,
            signature);

        if (validationResult == WebhookSignatureValidationResult.SignatureKeyNotConfigured)
        {
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Authorize.Net webhook signature key is not configured.");
        }

        if (validationResult != WebhookSignatureValidationResult.Valid)
        {
            return Unauthorized();
        }

        var storedWebhook = webhookStore.Save(Encoding.UTF8.GetString(rawBody));
        return Ok(new AuthorizeNetWebhookReceipt(storedWebhook.Id, storedWebhook.ReceivedAtUtc));
    }
}
