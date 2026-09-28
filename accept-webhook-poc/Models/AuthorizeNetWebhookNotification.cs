using System.Text.Json;

namespace accept_webhook_poc.Models;

/// <summary>
/// The top-level JSON notification Authorize.Net posts to a webhook endpoint.
/// </summary>
public sealed class AuthorizeNetWebhookNotification
{
    public Guid NotificationId { get; init; }

    public required string EventType { get; init; }

    public DateTimeOffset EventDate { get; init; }

    public Guid WebhookId { get; init; }

    public required JsonElement Payload { get; init; }
}
