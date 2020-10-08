using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(UserForRegisterDto credentials)
        {

            if (string.IsNullOrWhiteSpace(credentials.Username))
                return BadRequest("Username can't be empty");

            if (string.IsNullOrWhiteSpace(credentials.Password))
                return BadRequest("Password can't be empty");

            credentials.Username = credentials.Username.ToLower();

            if (await _repo.UserExists(credentials.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User
            {
                Username = credentials.Username
            };

            var createdUser = await _repo.Register(userToCreate, credentials.Password);

            return StatusCode(201);

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDto credentials)
        {

            if (string.IsNullOrWhiteSpace(credentials.Username))
                return BadRequest("Username can't be empty");

            if (string.IsNullOrWhiteSpace(credentials.Password))
                return BadRequest("Password can't be empty");

            var userFromRepo = await _repo.Login
                (credentials.Username.ToLower(), credentials.Password);

            if (userFromRepo == null) { return StatusCode(401, "Unauthorized"); }

            // Create a login Token when a login request comes in!
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                new Claim(ClaimTypes.Name, userFromRepo.Username)
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_config.GetSection("AppSettings:Token").Value));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var tokenDescriptor = new SecurityTokenDescriptor 
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };

            var tokenHandler = new JwtSecurityTokenHandler();

            var token = tokenHandler.CreateToken(tokenDescriptor);

            return Ok(new {
                token = tokenHandler.WriteToken(token)
            });

        }

    }
}