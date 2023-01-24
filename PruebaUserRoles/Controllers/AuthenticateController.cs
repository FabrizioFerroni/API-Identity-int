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
using PruebaUserRoles.Services.Interfaces;
using PruebaUserRoles.Data;
using System.Web;
using NLog.Fluent;
using PruebaUserRoles.Dto.Email;
using Newtonsoft.Json.Linq;
using MailKit.Net.Imap;


namespace PruebaUserRoles.Controllers
{
    [Route("auth")]
    [ApiController]
    [Authorize]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticateController> _logger;
        private readonly IEmailService _emailService;
        public const string Id = "id";

        public AuthenticateController(
           UserManager<User> userManager,
           SignInManager<User> signManager,
           RoleManager<Role> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            ILogger<AuthenticateController> logger)
        {
            _userManager = userManager;
            _signManager = signManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
        }

        [HttpPost("iniciarsesion")]
        [AllowAnonymous]
        public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginModel model)
        {
            var response = new LoginResponse();
            var origin = Request.Headers["origin"];
            try
            {

                String timeStamp = ToUnixTime(DateTime.Now);

                var user = await _userManager.FindByNameAsync(model.Username);

                if (user.EmailConfirmed == false)
                {
                    _logger.LogWarning("El usuario " + user.UserName + " no ha verificado la cuenta que acaba de registrar");
                    return BadRequest(new Response { Status = 400, Message = "No has verificado tu usuario, por favor verifica tu cuenta" });
                }

                if (user.TwoFactorEnabled)
                {
                    await _signManager.SignOutAsync();
                    await _signManager.PasswordSignInAsync(user, model.Password, false, true);
                    var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                    send2FACode(user.Email, token, user.UserName);
                    _logger.LogInformation($"Se ha enviado el codigo al email {user.Email} para que pueda iniciar sesión");

                    return Ok(new Response { Status = 200, Message = $"Se te ha enviado el codigo al email {user.Email} para que puedas iniciar sesión" });
                }

                await _signManager.SignOutAsync();
                var result2 = await _signManager.PasswordSignInAsync(model.Username, model.Password, false, true);

                if (result2.IsLockedOut)
                {
                    sendBlockOut(user.Email,origin, user.UserName);
                    _logger.LogWarning($"El usuario {user.UserName} ha sido bloqueado por demasiados intentos fallidos");
                    return BadRequest(new Response { Status = 400,  Message = $"El usuario {user.UserName} ha sido bloqueado por demasiados intentos fallidos, se envio un mail con instrucciones a seguir. O espere 30 minutos para su reactivación." });
                }

                //if(user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                if (user != null && result2.Succeeded)
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
                    _logger.LogInformation("El usuario " + user.UserName + " se ha  logueado con éxito");

                    response.Status = 200;
                    response.Message = "Te has logueado con éxito";
                    response.Data = user;
                    response.Token = new JwtSecurityTokenHandler().WriteToken(token);
                    response.Expiration = token.ValidTo;

                    return Ok(response);
                }

                _logger.LogWarning($"{user.UserName} Usuario o contraseña incorrecta");
                return BadRequest(new Response { Status = 400, Message = "Usuario o contraseña incorrecta" });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Hubo un error para iniciar sesion {ex}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = $"Hubo un error para iniciar sesion {ex}" });
            }
        }

        [HttpPost("iniciarsesion/2fa")]
        [AllowAnonymous]
        public async Task<ActionResult> Login2FA([FromBody] Login2FA model)
        {
            try
            {
                String timeStamp = ToUnixTime(DateTime.Now);
                var user = await _userManager.FindByNameAsync(model.Username);
                var signIn = await _signManager.TwoFactorSignInAsync("Email", model.Code, false, false);
                if (signIn.Succeeded)
                {
                    if (user != null)
                    {

                        var authClaims = new List<Claim>
                    {
                            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                            new Claim(Id, user.Id.ToString()),
                            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                            new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer32),
                            new Claim(ClaimTypes.Name, user.UserName),
                    };

                        var userRoles = await _userManager.GetRolesAsync(user);
                        foreach (var role in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, role));
                        }

                        var jwtToken = GetToken(authClaims);
                        _logger.LogInformation("El usuario " + user.UserName + " se ha  logueado con éxito con verificacion 2FA");

                        return Ok(new
                        {
                            status = 200,
                            message = "Te has logueado con éxito con verificación 2FA   ",
                            token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                            expiration = jwtToken.ValidTo,
                            data = user,
                    });

                    }
                }


                
                    _logger.LogWarning($"El usuario {user.UserName} fue bloqueado o mando un codigo invalido");
                return NotFound(new Response { Message = $"El usuario {user.UserName} fue bloqueado o mando un codigo invalido" });
            } catch (Exception ex)
            {
                _logger.LogError($"Hubo un error para iniciar sesion con 2FA {ex}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = $"Hubo un error para iniciar sesion con 2FA {ex}" });

            }
        }

        [HttpPost("registrarse")]
        [AllowAnonymous]
        public async Task<IActionResult> RegisterUser([FromBody] RegisterModel model)
        {
            var origin = Request.Headers["origin"];
            var userExists = await _userManager.FindByNameAsync(model.Username);

            if (userExists != null)
            {
                _logger.LogWarning("El usuario " + model.Username + " que intenta registrar ya existe!");
                sendAlreadyRegisteredEmail(model.Email, origin);
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "El usuario (" + model.Username + ") que intenta registrar ya existe!" });
            }
            User user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username,
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                _logger.LogError("¡La creación del usuario " + model.Username + " falló! Verifique los detalles del usuario y vuelva a intentarlo.");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Message = "¡La creación del usuario " + model.Username + " falló! Verifique los detalles del usuario y vuelva a intentarlo." });
            }

            if (model.Role == "Admin")
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);

                await _userManager.AddToRoleAsync(user, UserRoles.User);

                _logger.LogInformation("Al usuario " + model.Username + " se les asignaron los roles de admin y user");
            }

            if (model.Role == "User")
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
                _logger.LogInformation("Al usuario " + model.Username + " se les asignaron los roles de user");

            }

            if (model.Role.IsNullOrEmpty())
            {
                _logger.LogWarning("No has seleccionado ningun rol para el usuario (" + model.Username + ") se le puso automaticamente el rol User");
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }

            sendVerificationEmail(user, origin, model.Email);
            _logger.LogInformation("Se creo el usuario " + model.Username + " con éxito! Se le envio un correo a la direccion " + model.Email + " para que confirme su cuenta.");
            return StatusCode(StatusCodes.Status201Created, new Response { Status = 201, Message = "Se creo el usuario " + model.Username + " con éxito! Por favor, revisa tu email (" + model.Email + ") para confirmar tu email", Data = user });
        }

        [HttpPost("crear-roles")]
        [AllowAnonymous]
        public async Task<IActionResult> createRole()
        {
            try
            {
                if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                    await _roleManager.CreateAsync(new Role(UserRoles.Admin));
                if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                    await _roleManager.CreateAsync(new Role(UserRoles.User));

                return StatusCode(StatusCodes.Status201Created, new Response { Status = 201, Message = "Se crearon los roles con éxito" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.ToString());
                return StatusCode(StatusCodes.Status500InternalServerError, ex);
            }
        }

        [HttpPost("activar-2fa")]
        [AllowAnonymous]
        public async Task<IActionResult> activate2FA([FromBody] Activate2FA dto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(dto.Email);

                user.TwoFactorEnabled = dto.IsActivated;

                var upd = await _userManager.UpdateAsync(user);

                if (!upd.Succeeded)
                {
                    _logger.LogWarning($"No se ha podido actualizar al usuario {user.UserName} con éxito");
                    return BadRequest($"No se ha podido actualizar al usuario {user.UserName} con éxito");
                }

                if (dto.IsActivated == false)
                {
                    _logger.LogInformation($"El usuario {user.UserName} desactivo la verificación en dos pasos con éxito");
                    return StatusCode(StatusCodes.Status200OK, new Response { Status = 200, Message = $"El usuario {user.UserName} desactivo la verificación en dos pasos con éxito" });
                }

                _logger.LogInformation($"El usuario {user.UserName} activo la verificación en dos pasos con éxito");
                return StatusCode(StatusCodes.Status200OK, new Response { Status = 200, Message = $"El usuario {user.UserName} activo la verificación en dos pasos con éxito" });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Hubo un error para actualizar el usuario {ex}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = $"Hubo un error para actualizar el usuario {ex}" });
            }
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
                _logger.LogWarning("No se encontro el usuario buscado");
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

        private void sendAlreadyRegisteredEmail(string email, string origin, string name = null)
        {
            DtoMail dto = new DtoMail();
            dto.Email = email;
            dto.Name = name;
            dto.Link = $"{origin}/auth/olvide-clave";

            var body = _emailService.GetEmailTemplate("emailexist", dto);

            _emailService.Send(
                to: email,
                subject: "Upss ese email ya se encuentra registrado. 😢",
                html: body
            );
            _logger.LogInformation($"Se envió con éxito el correo de que ya existe la cuenta de {email}");

        }

        [HttpPost("reverificarcuenta")]
        [AllowAnonymous]
        public async Task<IActionResult> reVerifyEmail([FromBody] ReVerifyUser model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                var origin = Request.Headers["origin"];

                if (user == null)
                {
                    _logger.LogWarning("No se encontro el usuario que pidio el cambio de clave");
                    return NotFound(new Response { Message = "No se encontro el usuario buscado" });
                }
                sendReVerificationEmail(user, origin, model.Email);
                _logger.LogInformation($"Se reenvio el token de verificacion de cuenta al correo: {model.Email}");
                return Ok(new Response { Status = 200, Message = $"Se reenvio el token de verificacion de cuenta al correo {model.Email}" });
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                _logger.LogError(ex.ToString());
                return StatusCode(500, ex);
            }
        }

        private async void sendVerificationEmail(User account, string origin, string email)
        {
            var token = HttpUtility.UrlEncode(await _userManager.GenerateEmailConfirmationTokenAsync(account));

            DtoMail cm = new DtoMail();
            cm.Link = $"{origin}/auth/verificarmail?token={token}&email={account.Email}";

            var body = _emailService.GetEmailTemplate("confirm", cm);

            _emailService.Send(
                to: account.Email,
                subject: "Gracias por crear su cuenta con nosotros 😊",
                html: body
            );


            _logger.LogInformation($"Se envió con éxito el correo de verificación de cuenta a {email}");

        }

        private async void sendReVerificationEmail(User account, string origin, string email)
        {
            var token = HttpUtility.UrlEncode(await _userManager.GenerateEmailConfirmationTokenAsync(account));
            var verifyUrl = $"{origin}/auth/verificarmail?token={token}&email={account.Email}";

            DtoMail dto = new DtoMail();
            dto.Link = verifyUrl;

            var body = _emailService.GetEmailTemplate("reconfirm", dto);

            _emailService.Send(
                to: account.Email,
                subject: "No te olvides de verificar tu cuenta",
                html: body
            );


            _logger.LogInformation($"Se re-envió con éxito el correo de verificación de cuenta a {email}");

        }

        [HttpGet("verificarmail")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user.EmailConfirmed == false)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                var origin = _configuration["JWT:ValidIssuer"];
                if (user == null)
                {
                    _logger.LogWarning("No se encontro el usuario que se busca con los parametros");
                    return NotFound(new Response { Message = "No se encontro el usuario buscado" });
                }

                if (!result.Succeeded)
                {
                    _logger.LogWarning($"El token que mando el usuario {user.UserName} es invalido");
                    return BadRequest(new Response { Status = 400, Message = "El token es invalido" });
                }
                else
                {
                    _logger.LogInformation("El usuario " + user.UserName + " confirmo con éxito su cuenta.");
                    sendActivatedAccount(origin, email);
                    _logger.LogInformation($"Se envio mail de correo validado al usuario {user.UserName}");
                    return Ok(new Response { Status = 200, Message = "Su correo electrónico confirmado con éxito" });
                }

            }
            else
            {
                _logger.LogInformation($"El usuario {user.Email} ya confirmo su cuenta.");
                return Ok(new Response { Status = 200, Message = $"Esta cuenta {user.Email} ya se encuentra verificada." });
            }
        }

        private async void sendActivatedAccount(string origin, string email, string name = null)
        {
            var user = await _userManager.FindByEmailAsync(email);

            DtoMail dto = new DtoMail();
            dto.Link_login = $"{origin}/auth/iniciarsesion";
            dto.Link_retro = $"{origin}/api/sugerencias";
            dto.Name = name;
            dto.Email = email;
            dto.From = _configuration["AppSettings:EmailFrom"];

            var body = _emailService.GetEmailTemplate("activated", dto);

            _emailService.Send(
                to: user.Email,
                subject: "Cuenta verificada con éxito 🙌",
                html: body
            );


            _logger.LogInformation($"Se re-envió con éxito el correo de verificación de cuenta a {email}");

        }

        [AllowAnonymous]
        [HttpPost("olvide-clave")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    _logger.LogWarning("No se encontro el usuario que pidio el cambio de clave");
                    return NotFound(new Response { Message = "No se encontro el usuario buscado" });
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var buillink = "id=" + user.Id + "&token=" + token;
                var origin = Request.Headers["origin"];

                sendPasswordResetEmail(buillink, model.Email, origin, user.UserName);

                _logger.LogInformation("El usuario " + user.UserName + " necesita revisar su correo " + user.Email + " para poder seguir los pasos de cambiar clave");
                return StatusCode(StatusCodes.Status200OK, new Response { Status = 200, Message = "Por favor revise su correo electrónico para instrucciones de restablecimiento de contraseña" });

            }
            catch (Exception e)
            {
                _logger.LogError($"Hubo un error para cambiar la clave {e}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = $"Hubo un error para cambiar la clave {e}" });
            }
        }

        private void sendPasswordResetEmail(string link, string email, string origin, string username, string name = null)
        {
            DtoMail dto = new DtoMail();
            dto.Link = $"{origin}/auth/cambiar-clave?{link}";
            dto.Email = email;
            dto.Name = name;
            dto.Username = username;

            var body = _emailService.GetEmailTemplate("resetpassword", dto);

            _emailService.Send(
                to: email,
                subject: "Solicitud de restablecimiento de clave 🔑",
                html: body
            );
            _logger.LogInformation($"Se envió con éxito el correo de reestablecimiento de clave a {email}");
        }

        [HttpPost("cambiar-clave")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(int id, string token, ResetPasswordRequest dto)
        {
            try
            {
                var user = await _userManager.FindByIdAsync(id.ToString());
                if (user == null)
                {
                    _logger.LogWarning("No se encontro el usuario que se busca con los parametros");
                    return NotFound(new Response { Message = "No se encontro el usuario buscado" });
                }
                var origin = Request.Headers["origin"];
                token = token.Replace(' ', '+');
                var result = await _userManager.ResetPasswordAsync(user, token, dto.Password);


                if (!result.Succeeded)
                {
                    _logger.LogWarning("El token que mando el usuario es invalido");
                    return BadRequest(new Response { Status = 400, Message = "El token es invalido" });
                }

                user.LockoutEnd = null;

                _userManager.UpdateAsync(user);

                _logger.LogInformation("El usuario " + user.UserName + " cambio su contraseña con éxito.");
                sendPasswordConfirm(user.Email, origin, user.UserName);
                return Ok(new Response { Status = 200, Message = "Restablecimiento de contraseña con éxito, ahora puede iniciar sesión" });

            }
            catch (Exception e)
            {
                _logger.LogError($"Hubo un error para confirmar cambio de clave {e}");
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = 500, Message = $"Hubo un error para confirmar cambio de clave {e}" });
            }

        }

        private void sendPasswordConfirm(string email, string origin, string username, string name = null)
        {
            DtoMail dto = new DtoMail();
            dto.Link = $"{origin}/auth/iniciarsesion";
            dto.Name = name;
            dto.Username = username;

            var body = _emailService.GetEmailTemplate("passwordok", dto);

            _emailService.Send(
                to: email,
                subject: "Se cambio con éxito tu contraseña 🔐✔️",
                html: body
            );
            _logger.LogInformation($"Se cambio con éxito la contraseña del usuario con email {email}");
        }

        private void sendBlockOut(string email, string origin, string username, string name = null)
        {
            DtoMail dto = new DtoMail();
            dto.Link = $"{origin}/auth/olvide-clave";
            dto.Name = name;
            dto.Username = username;

            var body = _emailService.GetEmailTemplate("blockedout", dto);

            _emailService.Send(
                to: email,
                subject: "Lo sentimos 😢, te mandamos un instructivo para desbloquear tu cuenta",
                html: body
            );
            _logger.LogInformation($"Se envio con éxito el codigo de 2fa al usuario con email {email}");
        }

        private void send2FACode(string email, string code,  string username, string name = null)
        {
            DtoMail dto = new DtoMail();
            dto.Name = name;
            dto.Token = code;
            dto.Username = username;

            var body = _emailService.GetEmailTemplate("token2fa", dto);

            _emailService.Send(
                to: email,
                subject: "Código doble factor 🔐",
                html: body
            );
            _logger.LogInformation($"Se envio con éxito el codigo de 2fa al usuario con email {email}");
        }
    }
}
