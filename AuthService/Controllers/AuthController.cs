using System.Reflection.Metadata.Ecma335;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly RoleManager<IdentityRole> _roleManager;
    public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService, RoleManager<IdentityRole> roleManager)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _roleManager = roleManager;
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var user = new ApplicationUser
        {
            UserName = dto.Email,
            Email = dto.Email,
        };
        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors);

        if (!await _roleManager.RoleExistsAsync("Admin"))
            await _roleManager.CreateAsync(new IdentityRole("Admin"));
        if (!await _roleManager.RoleExistsAsync("User"))
            await _roleManager.CreateAsync(new IdentityRole("User"));

        await _userManager.AddToRoleAsync(user, "User");
        return Ok(result);

    }

    [HttpPost("login")]
    public async Task<ActionResult<AuthResponeDto>> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, dto.Password))
            return Unauthorized(new ErrorDto
            {
                Message = "Invalid email or password."
            });

        var token = await _tokenService.CreateTokenAsync(user);
        return Ok(new AuthResponeDto { Token = token, ExpiresAt = DateTime.UtcNow.AddMinutes(double.Parse("60")) });
    }
}