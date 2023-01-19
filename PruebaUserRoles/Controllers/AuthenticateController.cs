using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using PruebaUserRoles.Dto;
using PruebaUserRoles.Models;
using Microsoft.AspNetCore.Authorization;
using System.Linq;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace PruebaUserRoles.Controllers
{
    [Route("auth")]
    [ApiController]
    [Authorize]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IConfiguration _configuration;
        public const string Id = "Id";
        public const string Role = "role";
        //public const string Role = "Rol";
        public const string Username = "name";
        //public const string Username = "Username";
        public const string Email = "Email";

        public const string IssuedAt = "iat";


        //public const string userName = "";



        public AuthenticateController(
           UserManager<User> userManager,
           RoleManager<Role> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }
        [HttpPost]
        [Route("iniciarsesion")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            try
            {

                String timeStamp = ToUnixTime(DateTime.Now);

                var user = await _userManager.FindByNameAsync(model.Username);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var userRoles = await _userManager.GetRolesAsync(user);


                    var authClaims = new List<Claim>
                {
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        new Claim(Id, user.Id.ToString()),
                        new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer32),
                        new Claim(ClaimTypes.Name, user.UserName),
                };

                    foreach (var userRole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                    }

                    var token = GetToken(authClaims);

                    return Ok(new
                    {
                        Status = 200,
                        Message = "Te has logueado con éxito",
                        Data = user,
                        Token = new JwtSecurityTokenHandler().WriteToken(token),
                        Expiration = token.ValidTo
                    });
                }
                return Unauthorized(new Response { Status = 403, Message = "No estas autenticado" });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

            return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = "No ingreso al try-catch" });
        }



        [HttpPost]
        [Route("registrarse")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);

            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User already exists!" });

            User user = new()
            {
                Email = model.Email,
                NormalizedEmail = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
                NormalizedUserName = model.Username,
                EmailConfirmed = true,
                PhoneNumberConfirmed = false,
                TwoFactorEnabled = false,
                LockoutEnabled = false,
                AccessFailedCount = 0
            };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "User creation failed! Please check user details and try again." });

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new Role(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new Role(UserRoles.User));

            if (model.Role == "Admin")
            {
                if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                {
                    await _userManager.AddToRoleAsync(user, UserRoles.Admin);
                }
                if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                {
                    await _userManager.AddToRoleAsync(user, UserRoles.User);
                }
            }

            if (model.Role == "User")
            {
                if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                {
                    await _userManager.AddToRoleAsync(user, UserRoles.User);
                }
            }

            return StatusCode(StatusCodes.Status201Created, new Response { Status = 201, Message = "Usuario creado con éxito!", Data = result });
        }

        [HttpGet("me")]
        [Authorize(Roles = UserRoles.User)]
        public async Task<IActionResult> getUserLogged()
        {

            IEnumerable<Claim> userClaims = User.FindAll(ClaimTypes.Name);
            IEnumerable<string> userLogged = userClaims.Select(u => u.Value);
            List<string> listUser = userLogged.ToList();

            var userName = "";

            foreach (string users in listUser)
            {
                userName += users;

            };


            var user = await _userManager.FindByNameAsync(userName);
            if (user != null)
            {
                return Ok(new Response { Status = 200, Message = "Se encontro el usuario autentificado", Data = user });
            }
            else
            {
                return NotFound(new Response { Message = "No se ha encontrado el usuario" });
            }
        }



        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }

        public static String ToUnixTime(DateTime dateTime)
        {
            DateTimeOffset dto = new DateTimeOffset(dateTime.ToUniversalTime());
            return dto.ToUnixTimeSeconds().ToString();
        }

    }
}
