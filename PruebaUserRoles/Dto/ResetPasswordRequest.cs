using System.ComponentModel.DataAnnotations;

namespace PruebaUserRoles.Dto
{
    public class ResetPasswordRequest
    {
        [Required(ErrorMessage = "La contraseña es requerida")]
        [MinLength(8)]
        public string Password { get; set; }

        [Required]
        [Compare("Password", ErrorMessage = "La contraseña y la contraseña de confirmación no coinciden.")]
        public string ConfirmPassword { get; set; }
    }
}
