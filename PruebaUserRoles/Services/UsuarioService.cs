using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using PruebaUserRoles.Dto;
using PruebaUserRoles.Models;
using PruebaUserRoles.Services.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PruebaUserRoles.Services
{
    public class UsuarioService : IUsuarioService
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<UsuarioService> _logger;
        public const string Id = "id";
        private readonly IEmailService _emailService;

        public UsuarioService(
            UserManager<User> userManager,
           RoleManager<Role> roleManager,
            IConfiguration configuration,
            IEmailService emailService,
            ILogger<UsuarioService> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
        }

        public User Create(RegisterModel model)
        {
            throw new NotImplementedException();
        }

        public void Delete(int id)
        {
            throw new NotImplementedException();
        }

        public void ForgotPassword(ForgotPasswordRequest model, string origin)
        {
            throw new NotImplementedException();
        }

        public IEnumerable<User> GetAll()
        {
            throw new NotImplementedException();
        }

        public User GetById(int id)
        {
            throw new NotImplementedException();
        }

        public async void Login(LoginModel model)
        {
            throw new NotImplementedException();

            //try
            //{

            //    String timeStamp = ToUnixTime(DateTime.Now);

            //    var user = await _userManager.FindByNameAsync(model.Username);
            //    if (user.EmailConfirmed)
            //    {
            //        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            //        {
            //            var userRoles = await _userManager.GetRolesAsync(user);

            //            var authClaims = new List<Claim>
            //        {
            //                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            //                new Claim(Id, user.Id.ToString()),
            //                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            //                new Claim(JwtRegisteredClaimNames.Iat, timeStamp, ClaimValueTypes.Integer32),
            //                new Claim(ClaimTypes.Name, user.UserName),
            //        };



            //            foreach (var userRole in userRoles)
            //            {
            //                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            //            }

            //            var token = GetToken(authClaims);

            //            //return Ok(new
            //            //{
            //            //    Status = 200,
            //            //    Message = "Te has logueado con éxito",
            //            //    Data = user,
            //            //    Token = new JwtSecurityTokenHandler().WriteToken(token),
            //            //    Expiration = token.ValidTo
            //            //});

            //            var token_loged =  new JwtSecurityTokenHandler().WriteToken(token);
            //            return token;
            //            //return "";
            //        }
            //        //return BadRequest( new Response { Status = 400, Message = "Usuario o contraseña incorrecta" });
            //        throw new Exception("Usuario o contraseña incorrecta");

            //    }
            //    else
            //    {
            //       throw new Exception("No has verificado tu usuario, por favor verifica tu cuenta");
            //    }




            //}
            //catch (Exception ex)
            //{
            //    Console.WriteLine(ex.ToString());
            //}
        }

        public void Register(RegisterModel model, string origin)
        {
            throw new NotImplementedException();
        }

        public void ResetPassword(ResetPasswordRequest model)
        {
            throw new NotImplementedException();
        }

        public User Update(int id, UpdateRequest model)
        {
            throw new NotImplementedException();
        }

        public void ValidateResetToken(ValidateResetTokenRequest model)
        {
            throw new NotImplementedException();
        }

        public void VerifyEmail(string token)
        {
            throw new NotImplementedException();
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
