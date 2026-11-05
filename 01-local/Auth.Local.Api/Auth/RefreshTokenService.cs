using System.Security.Cryptography;
using System.Text;
using Auth.Local.Api.Contracts;
using Auth.Local.Api.Data;
using Auth.Local.Api.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Auth.Local.Api.Auth;

// Tarea Parte 1: refresh tokens con rotacion y deteccion de reutilizacion
public class RefreshTokenService(AppDbContext db, TokenService tokens, IOptions<JwtOptions> options)
{
    private readonly JwtOptions _jwt = options.Value;

    // valor aleatorio de 64 bytes (la tarea pide minimo 32) con RandomNumberGenerator
    public static string GenerarValor() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

    // en la BD solo se guarda esto, el SHA-256 en hexadecimal
    public static string CalcularHash(string valor) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(valor)));

    // se usa en login y en 2fa/verify: access token + refresh token nuevo
    public async Task<TokenPairResponse> CrearParAsync(User user)
    {
        var (valor, _) = await GuardarNuevoAsync(user.Id);
        return new TokenPairResponse(tokens.CreateAccessToken(user), valor);
    }

    // POST /api/auth/refresh
    // devuelve null si el token no sirve (el endpoint responde 401)
    public async Task<TokenPairResponse?> RotarAsync(string? valor)
    {
        if (string.IsNullOrWhiteSpace(valor))
            return null;

        var hash = CalcularHash(valor);
        var guardado = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
        if (guardado is null)
            return null;

        // si ya estaba revocado y lo vuelven a mandar, alguien lo robo o lo esta reusando.
        // por seguridad se revocan TODOS los tokens activos de ese usuario
        if (guardado.RevokedAt is not null)
        {
            var activos = await db.RefreshTokens
                .Where(t => t.UserId == guardado.UserId && t.RevokedAt == null)
                .ToListAsync();

            foreach (var t in activos)
                t.RevokedAt = DateTime.UtcNow;

            await db.SaveChangesAsync();
            return null;
        }

        if (guardado.ExpiresAt <= DateTime.UtcNow)
            return null;

        var user = await db.Users.FindAsync(guardado.UserId);
        if (user is null)
            return null;

        // rotacion: el viejo queda revocado y apunta al nuevo
        var (nuevoValor, nuevo) = await GuardarNuevoAsync(user.Id);
        guardado.RevokedAt = DateTime.UtcNow;
        guardado.ReplacedByTokenId = nuevo.Id;
        await db.SaveChangesAsync();

        return new TokenPairResponse(tokens.CreateAccessToken(user), nuevoValor);
    }

    // POST /api/auth/logout
    public async Task RevocarAsync(string? valor)
    {
        if (string.IsNullOrWhiteSpace(valor))
            return;

        var hash = CalcularHash(valor);
        var guardado = await db.RefreshTokens.SingleOrDefaultAsync(t => t.TokenHash == hash);
        if (guardado is not null && guardado.RevokedAt is null)
        {
            guardado.RevokedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
    }

    private async Task<(string valor, RefreshToken entidad)> GuardarNuevoAsync(int userId)
    {
        var valor = GenerarValor();
        var entidad = new RefreshToken
        {
            UserId = userId,
            TokenHash = CalcularHash(valor),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwt.RefreshTokenDays),
        };
        db.RefreshTokens.Add(entidad);
        await db.SaveChangesAsync();
        return (valor, entidad);
    }
}
