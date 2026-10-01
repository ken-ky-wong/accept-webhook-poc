using accept_webhook_poc.Models;
using accept_webhook_poc.Services;
using Microsoft.AspNetCore.Mvc;

namespace accept_webhook_poc.Controllers;

[ApiController]
[Route("api/accept-hosted/sessions")]
public sealed class AcceptHostedSessionsController(
    IAcceptHostedSessionService sessionService,
    ILogger<AcceptHostedSessionsController> logger) : ControllerBase
{
    /// <summary>Creates an Authorize.Net Accept Hosted session and returns its token.</summary>
    [HttpPost]
    [ProducesResponseType(typeof(AcceptHostedSessionResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status502BadGateway)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status503ServiceUnavailable)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status504GatewayTimeout)]
    public async Task<ActionResult<AcceptHostedSessionResponse>> Create(
        [FromBody] CreateAcceptHostedSessionRequest request,
        CancellationToken cancellationToken)
    {
        try
        {
            var token = await sessionService.CreateTokenAsync(request, cancellationToken);
            return Ok(new AcceptHostedSessionResponse(token));
        }
        catch (AcceptHostedConfigurationException exception)
        {
            logger.LogError(exception, "Accept Hosted configuration is incomplete or invalid");
            return Problem(
                statusCode: StatusCodes.Status503ServiceUnavailable,
                title: "Accept Hosted is not configured.");
        }
        catch (AcceptHostedGatewayException exception)
        {
            logger.LogWarning(
                exception,
                "Authorize.Net failed to create an Accept Hosted session with status {StatusCode}",
                exception.StatusCode);
            return Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Authorize.Net could not create the hosted payment session.",
                detail: exception.Message);
        }
        catch (HttpRequestException exception)
        {
            logger.LogError(exception, "Could not reach the Authorize.Net API");
            return Problem(
                statusCode: StatusCodes.Status502BadGateway,
                title: "Could not reach Authorize.Net.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Problem(
                statusCode: StatusCodes.Status504GatewayTimeout,
                title: "The Authorize.Net request timed out.");
        }
    }
}