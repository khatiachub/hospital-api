using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace hospital_api.Model
{
    public class ApplicationUser:IdentityUser
    {
        [Required]
        public override string? Email { get; set; }
        public string? Name { get; set; }
        public string? LastName { get; set; }
        public int? PrivateNumber { get; set; }
    }
}
