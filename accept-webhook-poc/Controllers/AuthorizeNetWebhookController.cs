using System.Text;
using System.Text.Json;
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
    AuthorizeNetWebhookSignatureValidator signatureValidator,
    ILogger<AuthorizeNetWebhookController> logger) : ControllerBase
{
    private const int MaximumSearchResults = 50;
    private static readonly JsonSerializerOptions WebJsonOptions = new(JsonSerializerDefaults.Web);

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
        [FromHeader(Name = "X-ANET-Signature")] string? signature,
        CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Received Authorize.Net webhook request {TraceIdentifier}",
            HttpContext.TraceIdentifier);

        await using var bodyBuffer = new MemoryStream();
        await Request.Body.CopyToAsync(bodyBuffer, cancellationToken);
        var rawBody = bodyBuffer.ToArray();
        logger.LogInformation(
            "Buffered {BodyLength} bytes for webhook request {TraceIdentifier}",
            rawBody.Length,
            HttpContext.TraceIdentifier);

        var validationResult = signatureValidator.Validate(
            rawBody,
            signature);

        logger.LogInformation(
            "Webhook request {TraceIdentifier} signature validation returned {ValidationResult}",
            HttpContext.TraceIdentifier,
            validationResult);

        if (validationResult == WebhookSignatureValidationResult.SignatureKeyNotConfigured)
        {
            logger.LogError(
                "Returning 503 for webhook request {TraceIdentifier}: the Authorize.Net signature key is not configured",
                HttpContext.TraceIdentifier);
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Authorize.Net webhook signature key is not configured.");
        }

        if (validationResult != WebhookSignatureValidationResult.Valid)
        {
            logger.LogWarning(
                "Returning 401 for webhook request {TraceIdentifier}: its signature was invalid",
                HttpContext.TraceIdentifier);
            return Unauthorized();
        }

        AuthorizeNetWebhookNotification? notification;
        try
        {
            notification = JsonSerializer.Deserialize<AuthorizeNetWebhookNotification>(rawBody, WebJsonOptions);
        }
        catch (JsonException exception)
        {
            logger.LogWarning(
                exception,
                "Returning 400 for webhook request {TraceIdentifier}: the signed body is not a valid Authorize.Net notification",
                HttpContext.TraceIdentifier);
            return BadRequest("The signed request body is not a valid Authorize.Net webhook notification.");
        }

        if (notification is null)
        {
            logger.LogWarning(
                "Returning 400 for webhook request {TraceIdentifier}: the signed body deserialized to null",
                HttpContext.TraceIdentifier);
            return BadRequest("The signed request body must contain an Authorize.Net webhook notification.");
        }

        logger.LogInformation(
            "Deserialized validated webhook {NotificationId} with event type {EventType}",
            notification.NotificationId,
            notification.EventType);
        logger.LogInformation("Saving validated webhook {NotificationId}", notification.NotificationId);
        var storedWebhook = webhookStore.Save(notification.NotificationId, Encoding.UTF8.GetString(rawBody));
        logger.LogInformation(
            "Returning 200 after accepting webhook {NotificationId} with event type {EventType}",
            notification.NotificationId,
            notification.EventType);
        return Ok(new AuthorizeNetWebhookReceipt(storedWebhook.Id, storedWebhook.ReceivedAtUtc));
    }

    /// <summary>
    /// Returns the most recently received stored webhook for an Authorize.Net notification ID.
    /// </summary>
    [HttpGet("{notificationId:guid}")]
    [ProducesResponseType(typeof(StoredAuthorizeNetWebhook), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public ActionResult<StoredAuthorizeNetWebhook> GetByNotificationId(Guid notificationId)
    {
        var webhook = webhookStore.GetByNotificationId(notificationId);
        return webhook is null ? NotFound() : Ok(webhook);
    }

    /// <summary>
    /// Lists up to the 50 most recently received webhooks within an optional receive-time range.
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(AuthorizeNetWebhookSearchResult), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public ActionResult<AuthorizeNetWebhookSearchResult> List(
        [FromQuery] DateTimeOffset? from,
        [FromQuery] DateTimeOffset? to)
    {
        var effectiveFrom = from ?? DateTimeOffset.MinValue;
        var effectiveTo = to ?? DateTimeOffset.UtcNow;

        if (effectiveFrom > effectiveTo)
        {
            return BadRequest("The 'from' value must be earlier than or equal to the 'to' value.");
        }

        var matchingWebhooks = webhookStore.GetByReceivedAt(
            effectiveFrom,
            effectiveTo,
            MaximumSearchResults + 1);

        var items = matchingWebhooks
            .Take(MaximumSearchResults)
            .Select(ToSummary)
            .ToArray();

        var message = matchingWebhooks.Count > MaximumSearchResults
            ? $"More matching webhooks exist; only the latest {MaximumSearchResults} are returned."
            : null;

        return Ok(new AuthorizeNetWebhookSearchResult(effectiveFrom, effectiveTo, items, message));
    }

    private static AuthorizeNetWebhookSummary ToSummary(StoredAuthorizeNetWebhook webhook)
    {
        var notification = JsonSerializer.Deserialize<AuthorizeNetWebhookNotification>(webhook.RawJson, WebJsonOptions)
            ?? throw new InvalidOperationException("A stored webhook could not be deserialized.");

        return new AuthorizeNetWebhookSummary(
            webhook.Id,
            webhook.ReceivedAtUtc,
            notification.NotificationId,
            notification.EventType,
            notification.EventDate,
            notification.WebhookId);
    }
}
