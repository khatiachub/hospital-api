using System.ComponentModel.DataAnnotations;
using System.Security.Policy;

namespace hospital_api.Model
{
    public class RecoverPassword
    {
       [Required]
       public  string NewPassword { get; set; }
       [Required]
       public string ConfirmPassword { get; set; }
       public string? Email { get; set; }
       public string? Token { get; set; }
    }
}
