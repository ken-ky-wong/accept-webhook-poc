namespace accept_webhook_poc.Models;

/// <summary>
/// Webhook metadata returned by a list request. The Authorize.Net payload is intentionally omitted.
/// </summary>
public sealed record AuthorizeNetWebhookSummary(
    Guid Id,
    DateTimeOffset ReceivedAtUtc,
    Guid NotificationId,
    string EventType,
    DateTimeOffset EventDate,
    Guid WebhookId);
