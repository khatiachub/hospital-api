using System.ComponentModel.DataAnnotations;

namespace hospital_api.Model
{
    public class UserEditModel
    {
        public string Name { get; set; }
        public string LastName { get; set; }
        //  public string? Email { get; set; }
        [StringLength(11, MinimumLength = 11, ErrorMessage = "PrivateNumber must be 11 characters long")]
        public string PrivateNumber { get; set; }
        public string? Category { get; set; } = null;
        public string? ProfileImage { get; set; } = null;
        public string? CV { get; set; } = null;
        public string? Description { get; set; } = null;
    }
}
