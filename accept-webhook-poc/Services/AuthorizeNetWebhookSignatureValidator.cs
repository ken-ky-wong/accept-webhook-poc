using System.Security.Cryptography;
using System.Text;

namespace accept_webhook_poc.Services;

public sealed class AuthorizeNetWebhookSignatureValidator(
    IConfiguration configuration,
    ILogger<AuthorizeNetWebhookSignatureValidator> logger)
{
    private const string SignaturePrefix = "sha512=";

    public WebhookSignatureValidationResult Validate(byte[] rawBody, string? signature)
    {
        logger.LogInformation("Validating Authorize.Net webhook signature");
        logger.LogInformation("Webhook raw body length: {BodyLength} bytes", rawBody.Length);
        logger.LogInformation("Webhook raw body Base64: {RawBodyBase64}", Convert.ToBase64String(rawBody));
        logger.LogInformation("Webhook raw body UTF-8: {RawBody}", Encoding.UTF8.GetString(rawBody));
        logger.LogInformation("Webhook X-ANET-Signature: {Signature}", signature ?? "<missing>");

        var signatureKey = configuration["AuthorizeNet-SignatureKey"];
        if (string.IsNullOrWhiteSpace(signatureKey))
        {
            logger.LogError("Authorize.Net webhook signature key is not configured");
            return WebhookSignatureValidationResult.SignatureKeyNotConfigured;
        }

        if (string.IsNullOrWhiteSpace(signature) ||
            !signature.StartsWith(SignaturePrefix, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Authorize.Net webhook signature is missing or does not start with {SignaturePrefix}",
                SignaturePrefix);
            return WebhookSignatureValidationResult.Invalid;
        }

        // AN function test
        try
        {
            logger.LogInformation("AN_HMACSHA512 encoded raw body:");
            var anHmac = AN_HMACSHA512(signatureKey, Encoding.UTF8.GetString(rawBody));
            logger.LogInformation("AN_HMACSHA512: {anHmac}", anHmac);
        }
        catch (Exception ex)
        {
            logger.LogError("AN_HMACSHA512 error: {ex}", ex);
            logger.LogError(ex.Message);
        }

        try
        {
            logger.LogInformation("AN_HMACSHA512 RAW body:");
            var anHmac = AN_HMACSHA512(signatureKey, rawBody);
            logger.LogInformation("AN_HMACSHA512: {anHmac}", anHmac);
        }
        catch (Exception ex)
        {
            logger.LogError("AN_HMACSHA512 error: {ex}", ex);
            logger.LogError(ex.Message);
        }

        byte[] receivedHash;
        byte[] key;

        try
        {
            key = Convert.FromHexString(signatureKey);
        }
        catch (FormatException)
        {
            logger.LogError("Configured Authorize.Net webhook signature key is not valid hexadecimal");
            return WebhookSignatureValidationResult.SignatureKeyNotConfigured;
        }

        try
        {
            receivedHash = Convert.FromHexString(signature[SignaturePrefix.Length..]);
        }
        catch (FormatException)
        {
            logger.LogWarning("Authorize.Net webhook signature hash is not valid hexadecimal");
            return WebhookSignatureValidationResult.Invalid;
        }

        using var hmac = new HMACSHA512(key);
        var calculatedHash = hmac.ComputeHash(rawBody);

        logger.LogInformation("Calculated HMACSHA512 hash: {CalculatedHash}", Convert.ToHexString(calculatedHash));
        logger.LogInformation("Received HMACSHA512 hash: {ReceivedHash}", Convert.ToHexString(receivedHash));

        if (CryptographicOperations.FixedTimeEquals(calculatedHash, receivedHash))
        {
            logger.LogInformation("Authorize.Net webhook signature validation succeeded");
            return WebhookSignatureValidationResult.Valid;
        }

        logger.LogWarning("Authorize.Net webhook signature validation failed: hashes did not match");
        return WebhookSignatureValidationResult.Invalid;
    }

    public static string AN_HMACSHA512(string key, string textToHash)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentNullException("HMACSHA512: key", "Parameter cannot be empty.");
        if (string.IsNullOrEmpty(textToHash))
            throw new ArgumentNullException("HMACSHA512: textToHash", "Parameter cannot be empty.");
        if (key.Length % 2 != 0 || key.Trim().Length < 2)
        {
            throw new ArgumentNullException("HMACSHA512: key", "Parameter cannot be odd or less than 2 characters.");
        }
        try
        {
            // This is the section to con vert byte array to hexadecimal string
            byte[] k = Enumerable.Range(0, key.Length)
                        .Where(x => x % 2 == 0)
                        .Select(x => Convert.ToByte(key.Substring(x, 2), 16))
                        .ToArray();
            HMACSHA512 hmac = new HMACSHA512(k);
            byte[] HashedValue = hmac.ComputeHash((new System.Text.ASCIIEncoding()).GetBytes(textToHash));
            return BitConverter.ToString(HashedValue).Replace("-", string.Empty);
        }
        catch (Exception ex)
        {
            throw new Exception("HMACSHA512: " + ex.Message);
        }
    }

    public static string AN_HMACSHA512(string key, byte[] rawBody)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentNullException("HMACSHA512: key", "Parameter cannot be empty.");
        if (rawBody == null || rawBody.Length == 0)
            throw new ArgumentNullException("HMACSHA512: rawBody", "Parameter cannot be null or empty.");
        if (key.Length % 2 != 0 || key.Trim().Length < 2)
        {
            throw new ArgumentNullException("HMACSHA512: key", "Parameter cannot be odd or less than 2 characters.");
        }
        try
        {
            // This is the section to con vert byte array to hexadecimal string
            byte[] k = Enumerable.Range(0, key.Length)
                        .Where(x => x % 2 == 0)
                        .Select(x => Convert.ToByte(key.Substring(x, 2), 16))
                        .ToArray();
            HMACSHA512 hmac = new HMACSHA512(k);
            byte[] HashedValue = hmac.ComputeHash(rawBody);
            return BitConverter.ToString(HashedValue).Replace("-", string.Empty);
        }
        catch (Exception ex)
        {
            throw new Exception("HMACSHA512: " + ex.Message);
        }
    }    
}

public enum WebhookSignatureValidationResult
{
    Valid,
    Invalid,
    SignatureKeyNotConfigured
}
