using System;
using System.Drawing;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Runtime.ConstrainedExecution;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Policy;
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
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.DotNet.Scaffolding.Shared.Messaging;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using Newtonsoft.Json;
using NuGet.Common;
using NuGet.Packaging.Signing;
using Org.BouncyCastle.Asn1.Pkcs;
using static System.Net.WebRequestMethods;
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
        private readonly IWebHostEnvironment _environment;


        public Authorization(IConfiguration configuration, IWebHostEnvironment environment,
            RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager, IEmailSender emailSender,SignInManager<ApplicationUser>signInManager)
        {
            this.userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailSender = emailSender;
            _environment = environment;
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

        

        //add user

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromForm] UserRegisterModel model )
        {
            var isExistUser = await userManager.FindByEmailAsync(model.Email);
            if (isExistUser != null)
            {
                return BadRequest("Email is already registered!");
            }

            var (profileImage, cv) = await WriteFiles(model.ProfileImage, model.CV);

            var newUser = new ApplicationUser()
            {
                Email = model.Email,
                Name = model.Name,
                UserName = model.Email,
                LastName = model.LastName,
                PrivateNumber = model.PrivateNumber,
                Role = model.Role,
                Description = model.Description,
                ProfileImage = profileImage,
                CV=cv,
                Category = model.Category,
                SecurityStamp = Guid.NewGuid().ToString(),
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

            var email = model.Email;
            string Token = await userManager.GenerateEmailConfirmationTokenAsync(newUser);
            var confirmationLink = $"http://localhost:4200/api/VerifyEmail/{HttpUtility.UrlEncode(Token)}/{HttpUtility.UrlEncode(email)}";
            var request = new EmailConfiguration()
            {
                To = model.Email,
                Subject = "Verify Email",
                Body = confirmationLink
            };
            await userManager.AddToRoleAsync(newUser,model.Role);
            await _emailSender.SendEmailAsync(request);
           

            return Ok(newUser);
        }

      


        //add admin doctor user
        [HttpPost("AddUsersByRoles")]
        
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public async Task<IActionResult> AddAdmin([FromForm] UserRegisterModel model)
        {
            var result = await Register(model);

            if (result!=null)
            {
                var user = await userManager.FindByEmailAsync(model.Email);
                var existingRoles = await userManager.GetRolesAsync(user);
                foreach (var role in existingRoles)
                {
                    await userManager.RemoveFromRoleAsync(user, role);
                }
                await userManager.AddToRoleAsync(user, model.Role);
                return Ok(user);
            }
            else
            {
                return BadRequest("User registration failed.");
            }
        }




        private async Task<(string ProfileImage, string CV)> WriteFiles(IFormFile profileImage, IFormFile cv)
        {
            string profileImageFilename = "";
            string cvFilename = "";
            try
            {
                if (profileImage != null)
                {
                    var profileImageExtension = "." + profileImage.FileName.Split('.')[profileImage.FileName.Split('.').Length - 1];
                    profileImageFilename = DateTime.Now.Ticks.ToString() + profileImageExtension;

                    var profileImageFilepath = Path.Combine(Directory.GetCurrentDirectory(), "Upload\\Files");

                    if (!Directory.Exists(profileImageFilepath))
                    {
                        Directory.CreateDirectory(profileImageFilepath);
                    }

                    var profileImageExactpath = Path.Combine(Directory.GetCurrentDirectory(), "Upload\\Files", profileImageFilename);
                    using (var profileImageStream = new FileStream(profileImageExactpath, FileMode.Create))
                    {
                        await profileImage.CopyToAsync(profileImageStream);
                    }
                }

                if (cv != null)
                {
                    var cvExtension = "." + cv.FileName.Split('.')[cv.FileName.Split('.').Length - 1];
                    cvFilename = DateTime.Now.Ticks.ToString() + cvExtension;

                    var cvFilepath = Path.Combine(Directory.GetCurrentDirectory(), "Upload\\Files");

                    if (!Directory.Exists(cvFilepath))
                    {
                        Directory.CreateDirectory(cvFilepath);
                    }

                    var cvExactpath = Path.Combine(Directory.GetCurrentDirectory(), "Upload\\Files", cvFilename);
                    using (var cvStream = new FileStream(cvExactpath, FileMode.Create))
                    {
                        await cv.CopyToAsync(cvStream);
                    }
                }
            }
            catch (Exception ex)
            {
                // Handle exceptions
            }
            return (profileImageFilename, cvFilename);
        }

        [HttpGet]
        [Route("DownloadFile/{filename}")]
        public async Task<IActionResult> DownloadFile(string filename)
        {
            var filepath = Path.Combine(Directory.GetCurrentDirectory(), "Upload\\Files", filename);

            // Read file content as bytes
            var bytes = await System.IO.File.ReadAllBytesAsync(filepath);

            // Return file content in response body
            return File(bytes, "application/pdf", filename);
        }




        //login
        [HttpPost("login")]
       // [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginModel model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return Unauthorized("Invalid email");
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
                var email = user.Email;
                string Token = await userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = $"http://localhost:4200/api/VerifyEmail/{HttpUtility.UrlEncode(Token)}/{HttpUtility.UrlEncode(email)}";
                var request = new EmailConfiguration()
                {
                    To = model.Email,
                    Subject = "Verify Email",
                    Body = confirmationLink
                };
                await _emailSender.SendEmailAsync(request);
               
               return Unauthorized("please verify email,verification link is sent");
            }
            if (await userManager.GetTwoFactorEnabledAsync(user))
            {
                string randomCode = GenerateRandomCode();
                DateTime expirationTime = DateTime.Now.AddMinutes(5);
                var request = new EmailConfiguration()
                {
                    To = model.Email,
                    Subject = "2-step verification code",
                    Body = randomCode
                };
                await _emailSender.SendEmailAsync(request);
              
                return Ok( new {Email=model.Email,Time=expirationTime,Code=randomCode});
            }
            else
            {
                return Ok(new { token = token, id=user.Id});
            }
        }

        //change email
        [HttpPost("sendemailchangecodetoemail/{Id}")]
        [Authorize]

        public async Task<IActionResult> SendCodeToEmail(string Id, [FromBody] CodeModel model)
        {
            var user = await userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }
            string randomCode = GenerateRandomCode();
            var request = new EmailConfiguration()
            {
                To = model.Email,
                Subject = "Email change verification code",
                Body = randomCode
            };
            await _emailSender.SendEmailAsync(request);
            return Ok(new { randomeCode=randomCode });
        }


        [HttpPost("enteremailchangecode/{Id}")]
        [Authorize]

        public async Task<bool> EnterEmailChangeCode(string Id, [FromBody] CodeModel model)
        {
            var user = await userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return false;
            }
            if (model.Code == model.NewCode)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        [HttpPost("enternewemail/{Id}")]
        [Authorize]

        public async Task<IActionResult> EnterNewEmail(string Id, [FromBody] CodeModel model)
        {
            var user = await userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }

            string randomCode = GenerateRandomCode();
            var request = new EmailConfiguration()
            {
                To = model.Email,
                Subject = "Email change verification code",
                Body = randomCode
            };
            await _emailSender.SendEmailAsync(request);
            return Ok(new {email=model.Email,randomeCode = randomCode });
        }

        [HttpPost("changeemail/{Id}")]
        [Authorize]

        public async Task<IActionResult> ChangeEmail(string Id, [FromBody] CodeModel model)
        {
            var user = await userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }
            if (model.Code==model.NewCode)
            {
                var token = await userManager.GenerateChangeEmailTokenAsync(user, model.Email);
                var result = await userManager.ChangeEmailAsync(user, model.Email, token);
                user.UserName = model.Email;
                await userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    return Ok(new { result = "Email updated successfully" });
                }
                else
                {
                    return BadRequest(result.Errors);
                }
            }
            else
            {
                return BadRequest(new { Message = "you are not allowed to change email" });
            }
        }
        








            // recover password
            [HttpPost("recoverpassword")]
        public async Task<IActionResult> RecoverPassword(CodeModel model)
        {
            if (model.Email == null)
            {
                return BadRequest("please enter email");
            }
           
                var user =await userManager.FindByEmailAsync(model.Email);
                if (user==null)
                {
                    return Unauthorized("your email is not registered");
                }
                else
                {
                    string randomCode = GenerateRandomCode();
                    DateTime expirationTime = DateTime.Now.AddMinutes(5);
                    var request = new EmailConfiguration()
                    {
                        To = model.Email,
                        Subject = "Password recovery code",
                        Body = randomCode
                    };
                    await _emailSender.SendEmailAsync(request);
                var data = new CodeModel()
                {
                    Time = expirationTime,
                    Code = randomCode,
                    Email = model.Email
                };
                    return Ok(data);
                }
        }
      

        //enter recover code
        [HttpPost("enter-password-recovery-code")]
        public async Task<IActionResult> EnterRecoveryCode(CodeModel model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("invalid login attemp");
            }
            if ((DateTime.Now - model.Time).TotalMinutes >= 5)
            {
                return BadRequest("Code has expired");
            }

            if (model.Code == model.NewCode)
            {
                var token= await userManager.GeneratePasswordResetTokenAsync(user);
                var data = new CodeModel()
                {
                    Email = model.Email,
                    Token = token
                };
                return Ok(data);
            }
            else
            {
                return BadRequest("code is invalid");
            }
        }
       

        //enter new password
        [HttpPost("enter-new-password")]
        public async Task<IActionResult> EnterNewPassword(RecoverPassword model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user != null)
            {
                if (model.NewPassword == model.ConfirmPassword)
                {
                    var result = await userManager.ResetPasswordAsync(user,model.Token, model.NewPassword);
                    if (result.Succeeded)
                    {
                        return Ok(user);
                    }
                    else
                    {
                        return Unauthorized("you are not allowed to reset password");
                    }
                }
                else
                {
                    return BadRequest("passwords dont match");
                }
            }
            else
            {
                return Unauthorized("user not found");
            }
        }







        // enter code
        [HttpPost("Auth-Code")]
        public async Task<IActionResult> VerifyCode(CodeModel model)
        {
            var user = await userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid Login Attempt.");
                return BadRequest("invald login attemp");
            }
            if ((DateTime.Now - model.Time).TotalMinutes >= 5)
            {
                return BadRequest("Code has expired");
            }
            else
            {
                if (model.NewCode == model.Code)
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
                    return Ok(new {token=token,id=user.Id});
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

        private static string DecodeUrlString(string url)
        {
            string newUrl;
            while ((newUrl = Uri.UnescapeDataString(url)) != url)
                url = newUrl;
            return newUrl;
        }

        //verify email
        [HttpGet("VerifyEmail/{Token}/{email}")]
        public async Task<IActionResult> VerifyEmail(string email, string Token)
        {

            var decodedEmail = DecodeUrlString(email);
            var decodedToken = DecodeUrlString(Token);
            var user = await userManager.FindByEmailAsync(decodedEmail);
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


            if (user != null)
            {
                var result = await userManager.ConfirmEmailAsync(user, decodedToken);
                if (result.Succeeded)
                {
                   
                    return Ok(new {result= "Email Verified Successfully" ,user=user,jwtToken=token});
                }
                
                else
                {
                    return BadRequest("Link has expired");
                }
            }
            else
            {
                return BadRequest("user not found");
            }  
        }



        // turn on 2step-authorization
        [HttpGet("2-step-authorization/{id}")]
        [Authorize]
        
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
                        return Ok(new {result = "two step authorization is on" });

                    }
                    else
                    {
                        return BadRequest("Failed to  two-step authorization");
                    }
                }
                else
                {
                    var result = await userManager.SetTwoFactorEnabledAsync(user, false);
                    if (result.Succeeded)
                    {
                        return Ok(new { result = "two step authorization is off" });
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
