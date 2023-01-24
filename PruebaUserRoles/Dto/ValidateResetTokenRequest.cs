using System.ComponentModel.DataAnnotations;

namespace PruebaUserRoles.Dto
{
    public class ValidateResetTokenRequest
    {
        [Required]
        public string Token { get; set; }
    }
}
