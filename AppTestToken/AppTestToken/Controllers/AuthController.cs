using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AppTestToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration _config;

        public AuthController(IConfiguration config)
        {
            _config = config;
        }


        [HttpGet]
        public async Task<ActionResult<object>> login()
        {
            string[] roles = ["admin", "user"];
            var roleclaims = roles.Select(x => new Claim(ClaimTypes.Role, x));
            List<Claim> claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Name,"seenu")
            }.Union(roleclaims).ToList();

            var token = new JwtSecurityTokenHandler().WriteToken(CreateToken(claims));
            var refreshToken = GenerateRefreshToken();

            //save refreshToken

            var res = new { accessToketoken = token, refreshToken = refreshToken };
            return Ok(res);
        }

        [HttpGet]
        [Route("refreshToken")]
        public async Task<ActionResult<object>> getrefeshToken(string accessToken, string refreshToken)
        {
            //validate the refreshToken
            var principal = GetPrincipalFromExpiredToken(accessToken);
            if (principal == null)
            {
                return BadRequest("Invalid Token");
            }
            var newAccessToken = new JwtSecurityTokenHandler().WriteToken(CreateToken(principal.Claims.ToList()));
            var newRefreshToken = GenerateRefreshToken();
            return Ok(new { accessToketoken = newAccessToken, refreshToken = newRefreshToken });
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = _config["JwtSetting:Issuer"],
                    ValidAudience = _config["JwtSetting:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSetting:Key"]))
                };

                var tokenHandler = new JwtSecurityTokenHandler();

                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

                if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                    throw new SecurityTokenException("Invalid token");

                return principal;
            }
            catch (Exception ex)
            {
                return null;
            }
            
        }
        private JwtSecurityToken CreateToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtSetting:Key"]));
            _ = int.TryParse(_config["JwtSetting:DurationInMinutes"], out int tokenValidityInMinutes);

            var token = new JwtSecurityToken(
                issuer: _config["JwtSetting:Issuer"],
                audience: _config["JwtSetting:Audience"],
                expires: DateTime.Now.AddMinutes(tokenValidityInMinutes),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
