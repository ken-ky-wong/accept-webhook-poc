using System.Collections.Concurrent;
using accept_webhook_poc.Models;

namespace accept_webhook_poc.Services;

/// <summary>
/// Process-local webhook storage. Its contents are lost when the application restarts.
/// </summary>
public sealed class InMemoryAuthorizeNetWebhookStore : IAuthorizeNetWebhookStore
{
    private readonly ConcurrentDictionary<Guid, StoredAuthorizeNetWebhook> _webhooks = new();

    public StoredAuthorizeNetWebhook Save(string rawJson)
    {
        var webhook = new StoredAuthorizeNetWebhook(
            Guid.NewGuid(),
            rawJson,
            DateTimeOffset.UtcNow);

        _webhooks[webhook.Id] = webhook;
        return webhook;
    }

    public IReadOnlyList<StoredAuthorizeNetWebhook> GetByReceivedAt(
        DateTimeOffset from,
        DateTimeOffset to,
        int maximumResults)
    {
        return _webhooks.Values
            .Where(webhook => webhook.ReceivedAtUtc >= from && webhook.ReceivedAtUtc <= to)
            .OrderByDescending(webhook => webhook.ReceivedAtUtc)
            .Take(maximumResults)
            .ToArray();
    }
}
