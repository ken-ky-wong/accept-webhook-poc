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
}
