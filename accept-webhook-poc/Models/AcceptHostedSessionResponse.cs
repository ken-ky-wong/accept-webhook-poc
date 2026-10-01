namespace accept_webhook_poc.Models;

/// <summary>Response containing the token used to open the Accept Hosted payment page.</summary>
public sealed record AcceptHostedSessionResponse(string Token);