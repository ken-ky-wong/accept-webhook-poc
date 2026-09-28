using accept_webhook_poc.Models;

namespace accept_webhook_poc.Services;

public interface IAuthorizeNetWebhookStore
{
    StoredAuthorizeNetWebhook Save(string rawJson);

    IReadOnlyList<StoredAuthorizeNetWebhook> GetByReceivedAt(
        DateTimeOffset from,
        DateTimeOffset to,
        int maximumResults);
}
