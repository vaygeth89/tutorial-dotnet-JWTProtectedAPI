

using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using JWTProtectedAPI.Models;
using JWTProtectedAPI.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTProtectedAPI.Controllers
{

    [Route("api/{Controller}/")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private AppDbContext _appDbContext;
        private readonly JWTBearerTokenSettings _jwtBearerTokenSettings;

        protected readonly UserManager<IdentityUser> _userManager;

        public AccountController(AppDbContext appDbContext, UserManager<IdentityUser> userManager, IOptions<JWTBearerTokenSettings> jwtTokenOptions)
        {
            _appDbContext = appDbContext;
            _jwtBearerTokenSettings = jwtTokenOptions.Value;
            _userManager = userManager;
        }
        [HttpPost]
        [Route("sign-up")]
        public async Task<ActionResult> SignUp(SignUpData signUpData)
        {
            //Todo add your business validation here
            //! You may want to add try/catch block to hanlde failed scenarios
            IdentityUser user = new IdentityUser()
            {
                Email = signUpData.Email,
                UserName = signUpData.Username,
            };
            IdentityResult identityResult = await _userManager.CreateAsync(user, signUpData.Password);
            if (identityResult.Succeeded)
            {
                string JWTToken = GenerateJWTToken(user);
                return Ok(new
                {
                    Token = JWTToken
                });
            }
            return BadRequest(new {
                Message = "Invalid data or weak password"
            });
        }

        [HttpPost]
        [Route("sign-in")]
        public async Task<ActionResult> SignIn(SignInData signInData)
        {
            //Todo add your business validation here
            //! You may want to add try/catch block to hanlde failed scenarios
            IdentityUser user = await ValidateUserCredentials(signInData);
            if(user == null){
                return BadRequest(new {
                    Message = "Invalid Credentials or User Doesn't not exist"
                });
            }
            string JWTToken = GenerateJWTToken(user);
            return Ok(new
            {
                Token = JWTToken
            });
        }
        [HttpGet]
        // [Authorize]
        [Route("my-profile")]
        public async Task<ActionResult<IdentityUser>> GetMyProfile()
        // public async Task<ActionResult<UserProfile>> GetMyProfile()
        {
            //Todo add your business validation here
            //! You may want to add try/catch block to hanlde failed scenarios
            List<IdentityUser> users = await _userManager.Users.ToListAsync();
            return Ok(users.First());

            string userEmail = User.FindFirst(ClaimTypes.Email)?.Value;
            IdentityUser user = await _appDbContext.Users.Where(e => e.Email == userEmail).FirstOrDefaultAsync();
            return Ok(new UserProfile()
            {
                Email = user.Email,
                Username = user.UserName,
                PhoneNumber = user.PhoneNumber
            });
        }

        private async Task<IdentityUser> ValidateUserCredentials(SignInData signInData)
        {
            IdentityUser user = await _userManager.FindByEmailAsync(signInData.Email);
            if (user != null)
            {
                var result = _userManager.PasswordHasher.VerifyHashedPassword(user, user.PasswordHash, signInData.Password);
                return result == PasswordVerificationResult.Failed ? null : user;
            }
            return null;
        }

        private string GenerateJWTToken(IdentityUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtBearerTokenSettings.SecretKey);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName.ToString()),
                    new Claim(ClaimTypes.Email, user.Email)
                }),

                Expires = DateTime.UtcNow.AddMinutes(_jwtBearerTokenSettings.ExpiryTimeInMinutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _jwtBearerTokenSettings.Audience,
                Issuer = _jwtBearerTokenSettings.Issuer
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}