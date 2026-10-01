using System.ComponentModel.DataAnnotations;

namespace accept_webhook_poc.Models;

/// <summary>Input for creating an Authorize.Net Accept Hosted payment session.</summary>
public sealed record CreateAcceptHostedSessionRequest
{
    [Range(typeof(decimal), "0.01", "999999.99")]
    public decimal Amount { get; init; }

    [Required, StringLength(20)]
    public required string InvoiceNumber { get; init; }
}