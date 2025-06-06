using AuthService.Models;

namespace AuthService.Services;

public interface ITokenService
{
    Task<string> CreateTokenAsync(ApplicationUser user);
}
