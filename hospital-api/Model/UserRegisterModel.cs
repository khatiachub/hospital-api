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
        [Required(ErrorMessage ="Name is required!")]
        public string Name { get; set; }
        [Required(ErrorMessage = "Lastname is required!")]
        public string LastName { get; set; }
        [Required(ErrorMessage = "Email is required!")]
        public string Email { get; set; }
        [Required(ErrorMessage = "PrivateNumber is required!")]
        public int PrivateNumber { get; set; }
        [Required(ErrorMessage = "Password is required!")]
        public string Password { get; set; }
        public bool EmailConfirmed { get; set; } = false;
        public bool TwoFactorEnabled { get; set; } = false;
    }


}
