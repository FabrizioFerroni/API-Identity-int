namespace PruebaUserRoles.Services.Interfaces
{
    public interface IEmailService
    {
        void Send(string to, string subject, string html, string from = null);
        string GetEmailTemplate<T>(string emailTemplate, T emailTemplateModel);
    }
}
