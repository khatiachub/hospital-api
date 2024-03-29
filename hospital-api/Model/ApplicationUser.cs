﻿using System.ComponentModel.DataAnnotations;
using System.Reflection.Metadata;
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
        public string? Role { get; set; }
        public string? Category { get; set; } = null;
        public string? ProfileImage { get; set; } = null;
        public string? CV { get; set; } = null;
        public string? Description { get; set; } = null;
    }
}
