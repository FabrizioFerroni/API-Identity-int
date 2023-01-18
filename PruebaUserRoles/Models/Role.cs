using Microsoft.AspNetCore.Identity;

namespace PruebaUserRoles.Models
{
    public class Role : IdentityRole<int>
    {
        public Role() { }
        public Role(string name) { Name = name; }
    }
}
