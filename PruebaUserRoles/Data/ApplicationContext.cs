using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PruebaUserRoles.Models;
using System.Configuration;

namespace PruebaUserRoles.Data
{
    public class ApplicationContext : IdentityDbContext<User, Role, int>
    {

        public ApplicationContext(DbContextOptions<ApplicationContext> options)
        : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }
        

    }
}
