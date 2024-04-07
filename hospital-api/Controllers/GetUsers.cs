using System.Data;
using hospital_api.DB;
using hospital_api.Model;
using hospital_api.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using NuGet.Common;

namespace hospital_api.Controllers
{
    [Route("api/")]
    [EnableCors("MyPolicy")]

    public class GetUsers : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly MyDbContext _dbContext;
        public GetUsers(IConfiguration configuration,MyDbContext dbContext,
           RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
            _dbContext = dbContext; 
        }

        //get all users
        [HttpGet("GetAllUsers")]
        [Authorize(Roles =StaticUserRoles.ADMIN)]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userManager.Users.ToListAsync();
            return Ok(users);
        }
        //get user
        [HttpGet("user/{Id}")]
        [Authorize]

        public async Task<IActionResult> GetUser(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound(); // User not found
            }
            return Ok(user);
        }

        //get doctor
        [HttpGet("doctor/{Id}")]

        public async Task<IActionResult> GetDoctor(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound(); // User not found
            }
            return Ok(user);
        }


        //delete user
        [HttpDelete("user/{Id}")]
        [Authorize]

        public async Task<IActionResult> DeleteUser(string Id)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }
            var deletedUser = await _userManager.DeleteAsync(user);
            if (deletedUser.Succeeded)
            {
                return Ok(new { result = "User deleted Successfully" });

            }
            else
            {
                return BadRequest("Failed to delete user");
            }
        }




        [HttpPost("ChangePassword/{Id}")]
        [Authorize]

        public async Task<IActionResult> ChangePassword(string Id, [FromBody] PasswordChange model)
        {
            
                var user = await _userManager.FindByIdAsync(Id);
                if (user == null)
                {
                    return NotFound();
                }
            var changePasswordResult = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (changePasswordResult.Succeeded)
            {
                return Ok(new { result = "Password changed successfully" });
            }
            else
            {
                var passwordErrors = string.Join(", ", changePasswordResult.Errors.Select(e => e.Description));
                return BadRequest($"Failed to change password. Errors: {passwordErrors}");
            }
        }

       

        //edit user
        [HttpPut("EditUser/{Id}")]
        [Authorize]

        public async Task<IActionResult> EditUser(string Id, [FromBody] UserEditModel model)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }
            if (model.Name != null)
            {
                user.Name = model.Name;
            }
            if (model.LastName != null)
            {
                user.LastName = model.LastName;
            }
            if (model.PrivateNumber != null)
            {
                user.PrivateNumber = model.PrivateNumber;
            }
           
            if (model.Category != null)
            {
                user.Category = model.Category;
            }
            
            if (model.Description != null)
            {
                user.Description = model.Description;
            }
            

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                return Ok(new { result ="User updated successfully"});
            }
            else
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return BadRequest($"Failed to edit User info. Errors: {errors}");
            }
        }


        //get by roles
        [HttpGet("GetByRoles/{Role}")]
       // [Authorize]

        public async Task<IActionResult> GetByRole(string Role)
        {
            var GetByRole = await _userManager.Users.Where(u => u.Role == Role).ToListAsync();

            return Ok(GetByRole);
        }

        [HttpGet("GetAllDoctors")]

        public async Task<IActionResult> GetByRole()
        {
            var GetByRole = await _userManager.Users.Where(u => u.Role == StaticUserRoles.DOCTOR).ToListAsync();
            return Ok(GetByRole);
        }



        //get by roles
        [HttpGet("GetByCategory/{category}")]

        public async Task<IActionResult> GetByCategory(string category)
        {
            var users = await _userManager.Users.Where(u => u.Category == category).ToListAsync();
            return Ok(users);
        }

        //get by roles
        [HttpGet("GetByName/{Name}/{LastName}")]
        public async Task<IActionResult> GetByName(string Name,string LastName)
        {
            var users = await _userManager.Users.Where(u => u.Name == Name&&u.LastName==LastName).ToListAsync();
            return Ok(users);
        }

        [HttpPost("AddCategory")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public async Task<IActionResult> AddCategory([FromBody] CategoriesModel model)
        {
            // var categories = _dbContext.Categories.ToList();
            _dbContext.Add(model);
            _dbContext.SaveChanges();
            return Ok(model);

        }

        [HttpGet("GetCategory")]
        public async Task<IActionResult> GetCategory()
        {
             var categories = _dbContext.Categories.ToList();
            return Ok(categories);

        }

        [HttpPut("EditCategory/{Id}")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public async Task<IActionResult> EditCategory([FromBody] CategoriesModel model, int Id)
        {
             var categories = _dbContext.Categories.Find(Id);
            categories.Category = model.Category;

            _dbContext.SaveChanges();
            return Ok();

        }
        [HttpDelete("DeleteCategory/{Id}")]
        [Authorize(Roles = StaticUserRoles.ADMIN)]
        public async Task<IActionResult> DeleteCategory(int Id)
        {
            var categories = _dbContext.Categories.Find(Id);
            _dbContext.Categories.Remove(categories);
            _dbContext.SaveChanges();
            return Ok();

        }

        

    }




}
