using hospital_api.DB;
using hospital_api.Model;
using hospital_api.Objects;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace hospital_api.Controllers
{
    [Route("api/")]
    [EnableCors("MyPolicy")]

    public class GetUsers : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public GetUsers(IConfiguration configuration,
           RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
           
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
                return Ok("User deleted Successfully");
            }
            else
            {
                return BadRequest("Failed to delete user");
            }
        }

        //edit user
        [HttpPut("EditUser/{Id}")]
        [Authorize]

        public async Task<IActionResult> EditUser(string Id,UserEditModel model)
        {
            var user = await _userManager.FindByIdAsync(Id);
            if (user == null)
            {
                return NotFound();
            }
            user.Name = model.Name;
            user.LastName = model.LastName;
            user.Email = model.Email;
            user.PasswordHash = model.Password;
            user.Category = model.Category;
            user.CV = model.CV;
            user.PrivateNumber = model.PrivateNumber;
            user.Description = model.Description;
            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
            {
                return Ok("User information updated successfully");
            }
            else
            {
                return BadRequest("Failed to edit User info");
            }
        }


        //get by roles
        [HttpGet("GetByRoles/{Role}")]
        [Authorize]

        public async Task<IActionResult> GetByRole(string Role)
        {
            var GetByRole = await _userManager.GetUsersInRoleAsync(Role);
            return Ok(GetByRole);
        }

        //get by roles
        [HttpGet("GetByCategory/{category}")]
        [Authorize]

        public async Task<IActionResult> GetByCategory(string category)
        {
            var users = await _userManager.Users.Where(u => u.Category == category).ToListAsync();
            return Ok(users);
        }

        //get by roles
        [HttpGet("GetByName/{Name}/{LastName}")]
        [Authorize]
        public async Task<IActionResult> GetByName(string Name,string LastName)
        {
            var users = await _userManager.Users.Where(u => u.Name == Name&&u.LastName==LastName).ToListAsync();
            return Ok(users);
        }



    }
}
