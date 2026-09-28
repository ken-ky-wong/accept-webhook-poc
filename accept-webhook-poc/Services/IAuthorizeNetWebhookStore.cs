using accept_webhook_poc.Models;

namespace accept_webhook_poc.Services;

public interface IAuthorizeNetWebhookStore
{
    StoredAuthorizeNetWebhook Save(Guid notificationId, string rawJson);

    StoredAuthorizeNetWebhook? GetByNotificationId(Guid notificationId);

    IReadOnlyList<StoredAuthorizeNetWebhook> GetByReceivedAt(
        DateTimeOffset from,
        DateTimeOffset to,
        int maximumResults);
}
