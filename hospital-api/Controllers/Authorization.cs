using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.ConstrainedExecution;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Azure;
using hospital_api.DB;
using hospital_api.Model;
using hospital_api.Objects;
using hospital_api.services;
using Humanizer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Newtonsoft.Json;
using NuGet.Packaging.Signing;
using Org.BouncyCastle.Asn1.Pkcs;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;

namespace hospital_api.Controllers
{
    [Route("api/")]
    [EnableCors("MyPolicy")]
    [ApiController]
    public class Authorization : ControllerBase
    {
       
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailSender _emailSender;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IMemoryCache _memoryCache;


        public Authorization(IConfiguration configuration, IMemoryCache memoryCache,
            RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager, IEmailSender emailSender,SignInManager<ApplicationUser>signInManager)
        {
            this.userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailSender = emailSender;
            _signInManager = signInManager;
            _memoryCache = memoryCache;
        }


        [HttpPost("seed-roles")]
        public async Task<IActionResult> SeedRoles()
        {
            bool isAdminRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.ADMIN);
            bool isDoctorRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.DOCTOR);
            bool isUserRoleExists = await _roleManager.RoleExistsAsync(StaticUserRoles.USER);

            if (isAdminRoleExists && isDoctorRoleExists && isUserRoleExists)
            {
                return Ok("Role seeding is already done");
            }
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.ADMIN));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.DOCTOR));
            await _roleManager.CreateAsync(new IdentityRole(StaticUserRoles.USER));
            return Ok("Role seeding done successfully");

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegisterModel model)
        {
            var isExistUser = await userManager.FindByEmailAsync(model.Email);
            if (isExistUser != null)
            {
                return BadRequest("Email is already registered!");
            }

            var newUser = new ApplicationUser()
            {
                Email = model.Email,
                Name = model.Name,
                UserName = model.Name,
                LastName = model.LastName,
                PrivateNumber = model.PrivateNumber
            };

            var createUser = await userManager.CreateAsync(newUser, model.Password);
            if (!createUser.Succeeded)
            {
                var errorString = "User creation failed because: ";
                foreach (var error in createUser.Errors)
                {
                    errorString += error.Description + " ";
                }
                return BadRequest(errorString);
            }

            DateTime expirationTime = DateTime.Now.AddMinutes(30);
            string timestamp = expirationTime.ToString("yyyy-MM-ddTHH:mm:ssZ");
            string Timestamp = timestamp.Replace(":", "%3A");
            
            //{Uri.EscapeDataString(token)}
            string token = await userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var confirmationLink = $"http://localhost:5134/api/verifyemail/{Uri.EscapeDataString(newUser.Email)}/{Timestamp}";
            var request = new EmailConfiguration()
            {
                To = model.Email,
                Subject = "Verify Email",
                Body = confirmationLink

            };
            await userManager.AddToRoleAsync(newUser, StaticUserRoles.USER);
            await _emailSender.SendEmailAsync(request);
            return Ok("Email sent successfully");
        }

        //login
        [HttpPost("login")]
       // [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginModel model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Unauthorized("Invalid credentials");
            }
            var isPasswordCorrect = await userManager.CheckPasswordAsync(user, model.Password);
            if (!isPasswordCorrect)
            {
                return Unauthorized("Invalid password");
            }
            var userRoles = await userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("JWTID",Guid.NewGuid().ToString()),
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var token = GenerateNewJsonWebToken(authClaims);
            if (!user.EmailConfirmed)
            {
                return Unauthorized("please verify email");
            }
            if (await userManager.GetTwoFactorEnabledAsync(user))
            {
                string randomCode = GenerateRandomCode();
                DateTime expirationTime = DateTime.Now.AddMinutes(5);
                // await _signInManager.SignOutAsync();
                var request = new EmailConfiguration()
                {
                    To = model.Email,
                    Subject = "2-step verification code",
                    Body = $"Your verification code is: {randomCode}. It will expire at {expirationTime}."
                };
                await _emailSender.SendEmailAsync(request);
                _memoryCache.Set("VerificationEmail", model.Email);
                _memoryCache.Set("code", randomCode,expirationTime);
                return Ok("Verification code sent. Please check your email.");
            }
            else
            {
                return Ok(token);
            }
        }
        


        // enter code
        [HttpPost("Auth-Code")]
        //[AllowAnonymous]
        public async Task<IActionResult> VerifyCode(CodeModel model, [FromServices] IMemoryCache memoryCache)
        {

            if (!memoryCache.TryGetValue("VerificationEmail", out string email))
            {
                return BadRequest("Email is missing in the cache");
            }
            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                return BadRequest("invald login attemp");
            }

            if (!memoryCache.TryGetValue("code",out string code))
            {
                return BadRequest("code is required");
            }
            else
            {
                if (code == model.Code)
                {
                var userRoles = await userManager.GetRolesAsync(user);
                var authClaims = new List<Claim>
                {
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.NameIdentifier,user.Id),
                new Claim("JWTID",Guid.NewGuid().ToString()),
                };
                    foreach (var userRole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                    }
                    var token = GenerateNewJsonWebToken(authClaims);
                    return Ok(token);
                }
                else
                {
                    return BadRequest("code is not correct");
                }
            }
        }







        private string GenerateRandomCode()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            var random = new Random();
            var code = new string(Enumerable.Repeat(chars, 4)
                .Select(s => s[random.Next(s.Length)]).ToArray());
            return code;
        }



        private string GenerateNewJsonWebToken(List<Claim> claims)
        {
            var authSecret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var tokenObject = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.MaxValue,
                claims: claims,
                signingCredentials: new SigningCredentials(authSecret, SecurityAlgorithms.HmacSha256)
            );
            string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);
            return token;
        }


        //verify email
        [HttpGet("verifyemail/{email}/{Timestamp}")]
        public async Task<IActionResult> VerifyEmail(string email, string Timestamp)
        {
            var user = await userManager.FindByEmailAsync(email);
            DateTime timestampString = DateTime.ParseExact(Timestamp, "yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            DateTime currentTime = DateTime.Now;
            if (user == null)
            {
                return BadRequest("User not found");
            }
            else if ((currentTime - timestampString).TotalMinutes > 30)
            {
                return BadRequest("Link is expired");
            }
            else
            {
                user.EmailConfirmed = true;
                
                await userManager.UpdateAsync(user);
                return Ok("Email verified successfully");
            }
        }

        // turn on 2step-authorization
        [HttpGet("2-step-authorization/{id}")]
        [Authorize(Roles =StaticUserRoles.USER)]
        
        public async Task<IActionResult> TwostepAuthentication(string Id)
        {
             var user =await userManager.FindByIdAsync(Id);
             if (user == null)
              {
                 return NotFound("user not found");
             }
              else
             {
                var is2FAEnabled = await userManager.GetTwoFactorEnabledAsync(user);
                if (!is2FAEnabled)
                {
                    var result = await userManager.SetTwoFactorEnabledAsync(user, true);
                    if (result.Succeeded)
                    {
                        return Ok("two step authorization is on");
                    }
                    else
                    {
                        return Ok("Failed to  two-step authorization");
                    }
                }
                else
                {
                    var result = await userManager.SetTwoFactorEnabledAsync(user, false);
                    if (result.Succeeded)
                    {
                        return Ok("Two-step authorization is off");
                    }
                    else
                    {
                        return BadRequest("Failed to disable two-step authorization");
                    }
                }
             }
        }

    } 
}
