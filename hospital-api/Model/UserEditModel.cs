using System.ComponentModel.DataAnnotations;

namespace hospital_api.Model
{
    public class UserEditModel
    {
        public string? Name { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public int? PrivateNumber { get; set; }
        public string? Password { get; set; }
        public bool? EmailConfirmed { get; set; } = false;
        public bool? TwoFactorEnabled { get; set; } = false;
        public string? Role { get; set; }
        public string? Category { get; set; } = null;
        public string? ProfileImage { get; set; } = null;
        public string? CV { get; set; } = null;
        public string? Description { get; set; } = null;
    }
}
