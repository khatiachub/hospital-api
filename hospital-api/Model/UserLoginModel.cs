using System.ComponentModel.DataAnnotations;

namespace hospital_api.Model
{
    public class UserLoginModel
    {
        [Required(ErrorMessage ="Email is required")]
        public string Email { get; set; }
        [Required(ErrorMessage ="Password is required")]
        public string Password { get; set; }
        public bool EmailConfirmed { get; set; } = false;
    }
}
