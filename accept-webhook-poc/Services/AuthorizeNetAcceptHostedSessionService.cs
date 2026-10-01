using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using accept_webhook_poc.Models;
using Microsoft.AspNetCore.WebUtilities;

namespace accept_webhook_poc.Services;

public sealed class AuthorizeNetAcceptHostedSessionService(
    HttpClient httpClient,
    IConfiguration configuration) : IAcceptHostedSessionService
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<string> CreateTokenAsync(
        CreateAcceptHostedSessionRequest request,
        CancellationToken cancellationToken)
    {
        var apiLoginId = configuration["AuthorizeNet:ApiLoginId"];
        var transactionKey = configuration["AuthorizeNet:TransactionKey"];
        var apiEndpoint = configuration["AuthorizeNet:ApiEndpoint"];
        var receiptUrl = configuration["AcceptHosted:ReceiptUrl"];
        var cancelUrl = configuration["AcceptHosted:CancelUrl"];

        if (string.IsNullOrWhiteSpace(apiLoginId) || string.IsNullOrWhiteSpace(transactionKey))
        {
            throw new AcceptHostedConfigurationException(
                "Authorize.Net API Login ID and Transaction Key must be configured.");
        }

        if (!Uri.TryCreate(apiEndpoint, UriKind.Absolute, out var apiUri) || apiUri.Scheme != Uri.UriSchemeHttps)
        {
            throw new AcceptHostedConfigurationException(
                "Authorize.Net API endpoint must be an absolute HTTPS URL.");
        }

        if (!IsHttpUrl(receiptUrl) || !IsHttpUrl(cancelUrl))
        {
            throw new AcceptHostedConfigurationException(
                "Accept Hosted receipt and cancel URLs must be absolute HTTP or HTTPS URLs.");
        }

        var requestBody = new
        {
            getHostedPaymentPageRequest = new
            {
                merchantAuthentication = new
                {
                    name = apiLoginId,
                    transactionKey
                },
                transactionRequest = new
                {
                    transactionType = "authCaptureTransaction",
                    amount = request.Amount,
                    order = new
                    {
                        invoiceNumber = request.InvoiceNumber,
                        description = "Product Description"
                    }
                },
                hostedPaymentSettings = new
                {
                    setting = new[]
                    {
                        Setting("hostedPaymentButtonOptions", new { text = "Pay" }),
                        Setting("hostedPaymentReturnOptions", new
                        {
                            showReceipt = false,
                            url = QueryHelpers.AddQueryString(receiptUrl!, "order", request.InvoiceNumber),
                            urlText = "Continue to receipt",
                            cancelUrl = QueryHelpers.AddQueryString(cancelUrl!, "order", request.InvoiceNumber),
                            cancelUrlText = "Cancel"
                        }),
                        Setting("hostedPaymentOrderOptions", new { show = false }),
                        Setting("hostedPaymentPaymentOptions", new { cardCodeRequired = true }),
                        Setting("hostedPaymentBillingAddressOptions", new { show = true, required = true }),
                        Setting("hostedPaymentShippingAddressOptions", new { show = false, required = false }),
                        Setting("hostedPaymentSecurityOptions", new { captcha = false }),
                        Setting("hostedPaymentStyleOptions", new { bgColor = "green" }),
                        Setting("hostedPaymentCustomerOptions", new { showEmail = true, requiredEmail = true })
                    }
                }
            }
        };

        using var response = await httpClient.PostAsJsonAsync(
            apiUri,
            requestBody,
            JsonOptions,
            cancellationToken);

        AuthorizeNetApiResponse? apiResponse;
        try
        {
            await using var responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var responseDocument = await JsonDocument.ParseAsync(
                responseStream,
                cancellationToken: cancellationToken);
            var responseRoot = responseDocument.RootElement;
            if (responseRoot.TryGetProperty("getHostedPaymentPageResponse", out var wrappedResponse))
            {
                responseRoot = wrappedResponse;
            }

            apiResponse = responseRoot.Deserialize<AuthorizeNetApiResponse>(JsonOptions);
        }
        catch (JsonException exception)
        {
            throw new AcceptHostedGatewayException(
                $"Authorize.Net returned an unreadable response (HTTP {(int)response.StatusCode}).",
                exception);
        }

        var apiMessage = apiResponse?.Messages?.Message?.FirstOrDefault();
        var token = apiResponse?.Token;
        if (!response.IsSuccessStatusCode ||
            !string.Equals(apiResponse?.Messages?.ResultCode, "Ok", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(token))
        {
            var detail = apiMessage is null
                ? $"Authorize.Net did not create the hosted payment session (HTTP {(int)response.StatusCode})."
                : $"Authorize.Net returned {apiMessage.Code}: {apiMessage.Text}";
            throw new AcceptHostedGatewayException(detail, response.StatusCode);
        }

        return token;
    }

    private static object Setting<T>(string name, T value) => new
    {
        settingName = name,
        settingValue = JsonSerializer.Serialize(value, JsonOptions)
    };

    private static bool IsHttpUrl(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    private sealed record AuthorizeNetApiResponse(
        string? Token,
        AuthorizeNetMessages? Messages);

    private sealed record AuthorizeNetMessages(
        string? ResultCode,
        AuthorizeNetMessage[]? Message);

    private sealed record AuthorizeNetMessage(
        string? Code,
        string? Text);
}

public sealed class AcceptHostedConfigurationException(string message) : Exception(message);

public sealed class AcceptHostedGatewayException : Exception
{
    public AcceptHostedGatewayException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public AcceptHostedGatewayException(string message, HttpStatusCode statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode? StatusCode { get; }
}