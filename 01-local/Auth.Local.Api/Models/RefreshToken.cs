namespace Auth.Local.Api.Models;

// Refresh token guardado en la BD.
// Ojo: aqui NO se guarda el token, solo su hash SHA-256.
public class RefreshToken
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public int UserId { get; set; }

    public string TokenHash { get; set; } = "";

    public DateTime ExpiresAt { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // null = todavia se puede usar
    public DateTime? RevokedAt { get; set; }

    // cuando se rota, aqui queda el id del token nuevo
    public Guid? ReplacedByTokenId { get; set; }
}
