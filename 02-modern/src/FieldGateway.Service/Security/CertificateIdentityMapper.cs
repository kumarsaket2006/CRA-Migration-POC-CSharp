using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Indusoft.FieldGateway.Core.Diagnostics;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.Extensions.Options;

namespace Indusoft.FieldGateway.Service.Security;

/// <summary>
/// Maps a chain-validated client certificate to a gateway identity and roles using an explicit
/// SHA-256 thumbprint allow-list (fixes L05 / MR-01, CWE-306/862; IEC 62443-4-2 CR 1.2 / CR 2.1).
/// Unknown certificates are rejected even if they chain to a trusted CA.
/// </summary>
public sealed class CertificateIdentityMapper(IOptionsMonitor<GatewayOptions> options, ILogger<CertificateIdentityMapper> logger)
{
    public Task OnCertificateValidated(CertificateValidatedContext context)
    {
        var cert = context.ClientCertificate;
        string thumb = Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256));
        var client = options.CurrentValue.Clients.FirstOrDefault(c =>
            string.Equals(c.Sha256Thumbprint, thumb, StringComparison.OrdinalIgnoreCase));

        if (client is null)
        {
            GatewayLog.AuthenticationFailed(logger, Remote(context.HttpContext), "certificate not in allow-list");
            context.Fail("certificate not authorised");
            return Task.CompletedTask;
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, client.Name, ClaimValueTypes.String, context.Options.ClaimsIssuer),
            new("fg:thumbprint", thumb),
        };
        claims.AddRange(client.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
        context.Success();
        return Task.CompletedTask;
    }

    public Task OnAuthenticationFailed(CertificateAuthenticationFailedContext context)
    {
        GatewayLog.AuthenticationFailed(logger, Remote(context.HttpContext), context.Exception.GetType().Name);
        return Task.CompletedTask;
    }

    public static string ClientName(ClaimsPrincipal user) => user.Identity?.Name ?? "anonymous";

    private static string Remote(HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
}
