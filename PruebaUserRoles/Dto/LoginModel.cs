using System.ComponentModel.DataAnnotations;

namespace PruebaUserRoles.Dto
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Se requiere nombre de usuario")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Se requiere contraseña")]
        public string? Password { get; set; }
    }
}
