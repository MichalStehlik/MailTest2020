using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Util;
using Google.Apis.Util.Store;
using MailKit.Net.Imap;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using MimeKit;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace MailTest2020b.Services
{
    // https://github.com/jstedfast/MailKit/blob/master/GMailOAuth2.md
    public class EmailSender: IEmailSender
    {
        public string HtmlMessage { get; set; } // vlastnost pro vložení volitelného těla HTML zprávy
        public IConfiguration Configuration { get; protected set; } // konfigurace aplikace

        public EmailSender(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        /// <summary>
        /// Odeslání emailu
        /// </summary>
        /// <param name="email">emailová adresa příjemce</param>
        /// <param name="subject">předmět mailu</param>
        /// <param name="text">plain textová podoba obsahu</param>
        /// <returns>nic</returns>
        public async Task SendEmailAsync(string email, string subject, string text) 
        {
            var message = new MimeMessage(); // vytvoření mailové zprávy
            message.From.Add(new MailboxAddress(Configuration["EmailSender:FromName"], Configuration["EmailSender:From"]));
            message.To.Add(new MailboxAddress(email, email));
            message.Subject = subject;

            var bodyBuilder = new BodyBuilder();
            if (HtmlMessage != "") bodyBuilder.HtmlBody = HtmlMessage; // pokud máme HTML zprávu, tak ji připojíme
            bodyBuilder.TextBody = text;

            message.Body = bodyBuilder.ToMessageBody();

            // GMail OAUTH Flow
            var clientSecrets = new ClientSecrets
            {
                ClientId = Configuration["EmailSender:AppID"],
                ClientSecret = Configuration["EmailSender:AppSecret"]
            };

            var codeFlow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer
            {
                DataStore = new FileDataStore("CredentialCacheFolder", false),
                Scopes = new[] { "https://mail.google.com/" },
                ClientSecrets = clientSecrets
            });

            var codeReceiver = new LocalServerCodeReceiver();
            var authCode = new AuthorizationCodeInstalledApp(codeFlow, codeReceiver);

            var credential = await authCode.AuthorizeAsync(Configuration["EmailSender:AccountID"], CancellationToken.None);

            if (credential.Token.IsExpired(SystemClock.Default))
                await credential.RefreshTokenAsync(CancellationToken.None);

            var oauth2 = new SaslMechanismOAuth2(credential.UserId, credential.Token.AccessToken);

            Int32.TryParse(Configuration["EmailSender:Port"], out int port); // v konfiguraci je port uveden jako text, potřebujeme ho jako číslo
            using (var client = new SmtpClient()) // vytvoření SMTP klienta
            {
                await client.ConnectAsync(Configuration["EmailSender:Server"], port, SecureSocketOptions.StartTlsWhenAvailable);
                await client.AuthenticateAsync(oauth2);
                await client.SendAsync(message);
                await client.DisconnectAsync(true);
            }
        }
    }
}
