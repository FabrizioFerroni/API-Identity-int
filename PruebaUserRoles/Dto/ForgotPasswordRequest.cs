using System.ComponentModel.DataAnnotations;

namespace PruebaUserRoles.Dto
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
