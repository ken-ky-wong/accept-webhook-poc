namespace accept_webhook_poc.Models;

/// <summary>
/// Returned after a verified webhook has been stored in memory.
/// </summary>
public sealed record AuthorizeNetWebhookReceipt(Guid Id, DateTimeOffset ReceivedAtUtc);
