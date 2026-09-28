namespace accept_webhook_poc.Models;

/// <summary>
/// A verified Authorize.Net webhook retained for the lifetime of this application process.
/// </summary>
public sealed record StoredAuthorizeNetWebhook(
    Guid Id,
    Guid NotificationId,
    string RawJson,
    DateTimeOffset ReceivedAtUtc);
