using System.ComponentModel.DataAnnotations;

namespace PruebaUserRoles.Dto
{
    public class ReVerifyUser
    {
        [Required(ErrorMessage = "El email es obligatorio")]
        [EmailAddress(ErrorMessage = "El campo de correo electrónico no es una dirección de correo electrónico válida")]
        [DataType(DataType.EmailAddress, ErrorMessage = "El campo de correo electrónico no es una dirección de correo electrónico válida")]
        [RegularExpression(@"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$", ErrorMessage = "El campo de correo electrónico no es una dirección de correo electrónico válida")]
        public string Email { get; set; }
    }
}
