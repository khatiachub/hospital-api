using hospital_api.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace hospital_api.DB
{
        public class MyDbContext : IdentityDbContext <ApplicationUser>

    {
        public MyDbContext(DbContextOptions<MyDbContext> options) : base(options)
        {

        }
        public DbSet<CalendarModel> Calendar { get; set; }
        public DbSet<CategoriesModel> Categories { get; set; }



     

    }

}
