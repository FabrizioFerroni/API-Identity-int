using Microsoft.AspNetCore.Mvc;
using PruebaUserRoles.Dto;
using PruebaUserRoles.Models;

namespace PruebaUserRoles.Services.Interfaces
{
    public interface IUsuarioService
    {
        void Login(LoginModel model);
        //AuthenticateResponse RefreshToken(string token, string ipAddress);
        //void RevokeToken(string token, string ipAddress);
        void Register(RegisterModel model, string origin);
        void VerifyEmail(string token);
        void ForgotPassword(ForgotPasswordRequest model, string origin);
        void ValidateResetToken(ValidateResetTokenRequest model);
        void ResetPassword(ResetPasswordRequest model);
        IEnumerable<User> GetAll();
        User GetById(int id);
        User Create(RegisterModel model);
        User Update(int id, UpdateRequest model);
        void Delete(int id);
    }
}
