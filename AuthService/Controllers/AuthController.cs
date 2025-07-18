﻿using System.Reflection.Metadata.Ecma335;
using AuthService.DTOs;
using AuthService.Models;
using AuthService.Services;
using Microsoft.AspNetCore.Authorization;
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
    private readonly IConfiguration _config;
    public AuthController(UserManager<ApplicationUser> userManager, ITokenService tokenService, RoleManager<IdentityRole> roleManager, IConfiguration config)
    {
        _userManager = userManager;
        _tokenService = tokenService;
        _roleManager = roleManager;
        _config = config;
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto) 
    {

        if (await _userManager.FindByEmailAsync(dto.Email) != null)
        {
            return Conflict(new ErrorDto { Message = "Email is already in use." });
        }

        var user = new ApplicationUser
        {
            UserName = dto.Email,
            Email = dto.Email,
        };

        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded) //seedar roller
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
            return Unauthorized(new ErrorDto { Message = "Invalid email or password." });

        // Skapar token med Issuer/Audience från appsettings (ingen inparameterad Audience).
        var token = await _tokenService.CreateTokenAsync(user);

        return Ok(new AuthResponeDto
        {
            Token = token,
            ExpiresAt = DateTime.UtcNow.AddMinutes(double.Parse(_config["Jwt:ExpiresInMinutes"]!))
        });
    }


    [AllowAnonymous]
    [HttpPost("verify-email")] // Endpoint för att verifiera e-post
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest(new { message = "Email is Required" });
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return NotFound(new { message = "No User found" });
        }

        user.EmailConfirmed = true;
        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
        {
            return StatusCode(500, new { message = "Could not verify email" });
        }

        return Ok(new { message = "Email verified" });
    }
}