namespace accept_webhook_poc.Models;

public sealed record AuthorizeNetWebhookSearchResult(
    DateTimeOffset From,
    DateTimeOffset To,
    IReadOnlyList<AuthorizeNetWebhookSummary> Items,
    string? Message);
