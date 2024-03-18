using hospital_api.Model;

namespace hospital_api.services
{
    public interface IEmailSender
    {
        Task SendEmailAsync(EmailConfiguration request);
    }
}
