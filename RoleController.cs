using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using jwt_practice;

[ApiController]
[Route("[controller]")]

//[Authorize(Policy = "ApprenticePolicy")] // A todo el controlador
public class RoleController : ControllerBase
{
    [Authorize(Policy = "UserPolicy")]
    [HttpGet("user")]
    public IActionResult GetUser()
    {
        return Ok("User endpoint");
    }

    [Authorize(Policy = "ApprenticePolicy")]
    [HttpGet("apprentice")]
    public IActionResult GetApprentice()
    {
        return Ok("Apprentice endpoint");
    }

    [Authorize(Policy = "ExpertPolicy")]
    [HttpGet("expert")]
    public IActionResult GetExpert()
    {
        return Ok("Expert endpoint");
    }

    [Authorize(Policy = "AdminPolicy")]
    [HttpGet("admin")]
    public IActionResult GetAdmin()
    {
        return Ok("Admin endpoint");
    }

    [AllowAnonymous]
    [HttpPost("login_to_get_token")]
    public IActionResult LoginToGetToken([FromBody] LoginRequest request)
    {
        if (request.Username == "isaac" && request.Password == "isaac123")
        {
            var token = GenerateJwtToken(request.Role);
            return Ok(new { Token = token });
        }
        return Unauthorized(new { message = "Invalid credentials" });
    }

    private string GenerateJwtToken(string role)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes("llave_super_secreta_no_mostrar_a_nadie_Xd");
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Aud, "cualquiera"),
                new Claim(JwtRegisteredClaimNames.Iss, "isaac") 
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
}