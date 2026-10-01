using accept_webhook_poc.Models;

namespace accept_webhook_poc.Services;

public interface IAcceptHostedSessionService
{
    Task<string> CreateTokenAsync(
        CreateAcceptHostedSessionRequest request,
        CancellationToken cancellationToken);
}