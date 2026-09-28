using System.Security.Cryptography;

namespace accept_webhook_poc.Services;

public sealed class AuthorizeNetWebhookSignatureValidator(IConfiguration configuration)
{
    private const string SignaturePrefix = "sha512=";

    public WebhookSignatureValidationResult Validate(byte[] rawBody, string? signature)
    {
        var signatureKey = configuration["AuthorizeNet:WebhookSignatureKey"];
        if (string.IsNullOrWhiteSpace(signatureKey))
        {
            return WebhookSignatureValidationResult.SignatureKeyNotConfigured;
        }

        if (string.IsNullOrWhiteSpace(signature) ||
            !signature.StartsWith(SignaturePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return WebhookSignatureValidationResult.Invalid;
        }

        byte[] receivedHash;
        byte[] key;

        try
        {
            key = Convert.FromHexString(signatureKey);
            receivedHash = Convert.FromHexString(signature[SignaturePrefix.Length..]);
        }
        catch (FormatException)
        {
            return WebhookSignatureValidationResult.Invalid;
        }

        using var hmac = new HMACSHA512(key);
        var calculatedHash = hmac.ComputeHash(rawBody);

        return CryptographicOperations.FixedTimeEquals(calculatedHash, receivedHash)
            ? WebhookSignatureValidationResult.Valid
            : WebhookSignatureValidationResult.Invalid;
    }
}

public enum WebhookSignatureValidationResult
{
    Valid,
    Invalid,
    SignatureKeyNotConfigured
}
