using System.Net;
using hospital_api.Model;
using Microsoft.AspNetCore.Http.HttpResults;
using MimeKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using Org.BouncyCastle.Asn1.Esf;
namespace hospital_api.services
{
    public class EmailSender:IEmailSender
    {
        private readonly IConfiguration _config;

        public EmailSender(IConfiguration config)
        {
            _config =config;
        }
        public async Task SendEmailAsync(EmailConfiguration request)
        {
            try
            {
                var emailMessage = new MimeMessage();
                emailMessage.From.Add(MailboxAddress.Parse(_config.GetSection("userName").Value));
                emailMessage.To.Add(MailboxAddress.Parse(request.To));
                emailMessage.Subject = request.Subject;
                emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = request.Body };

                using var client = new SmtpClient();

                await client.ConnectAsync(_config.GetSection("SmtpServer").Value, 587, SecureSocketOptions.StartTls);
                await client.AuthenticateAsync("clinic181098@gmail.com", _config.GetSection("appPassword").Value);
                await client.SendAsync(emailMessage);
                await client.DisconnectAsync(true);
            }
            catch (Exception ex)
            {
                // Log the error or handle it in some way
                Console.WriteLine($"An error occurred while sending email: {ex.Message}");
                throw; // Rethrow the exception to propagate it further if needed
            }
        }

    }
}

//_config.GetSection("UserName").Value




