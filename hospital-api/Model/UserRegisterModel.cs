using System.ComponentModel.DataAnnotations;
using hospital_api.DB;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.EntityFrameworkCore;

namespace hospital_api.Model
{
    public class UserRegisterModel
    {
        [Required(ErrorMessage = "Name is required!")]
        [StringLength(50, MinimumLength = 5)]
        public string Name { get; set; }
        [Required(ErrorMessage = "Lastname is required!")]
        public string LastName { get; set; }
        [Required(ErrorMessage = "Email is required!")]
        public string Email { get; set; }
        [Required(ErrorMessage = "PrivateNumber is required!")]
        [StringLength(11, MinimumLength = 11, ErrorMessage = "PrivateNumber must be 11 characters long")]
        public string PrivateNumber { get; set; }
        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; }
        public bool EmailConfirmed { get; set; } = false;
        public bool TwoFactorEnabled { get; set; } = false;
        public string Role { get; set; }
        public string? Category { get; set; }=null;
        public IFormFile? ProfileImage { get; set; } = null;
        public IFormFile? CV { get; set; } = null;
        public string? Description { get; set; } = null;

    }


}
