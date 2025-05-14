namespace AuthService.DTOs;

public class AuthResponeDto
{
    public string Token { get; set; } = null!;
    public DateTime ExpiresAt { get; set; }
}
