using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PruebaUserRoles.Dto;
using System.Security.Claims;

namespace PruebaUserRoles.Controllers
{
    [Authorize]
    [Route("api/")]
    [ApiController]
    public class ApiController : ControllerBase
    {
        [HttpGet("user")]
        [Authorize(Roles = UserRoles.User)]
        public IActionResult getUser()
        {
            return Ok(new Response { Status = 200, Message = "Hola User, Si ves esto tenes el rol user" });

        }

        [HttpGet("admin")]
        [Authorize(Roles = UserRoles.Admin)]
        public IActionResult getAdmin()
        {
            return Ok(new Response { Status = 200, Message = "Hola Admin, Si ves esto tenes el rol admin y user" });
        }

        [HttpGet("roles")]
        [Authorize(Roles = UserRoles.Admin)]
        public IActionResult GetRoles()
        {
            IEnumerable<Claim> roleClaims = User.FindAll(ClaimTypes.Role);
            IEnumerable<string> roles = roleClaims.Select(r => r.Value);
            if (roles != null)
            {
            return Ok(new Response { Status = 200, Message = "Se encontraron los siguientes roles para el usuario autentificado.", Data = roles });
            } else
            {
                return NotFound(new Response { Message = "No encontré ningún rol para el usuario autentificado" });
            }

        }

    }
}
