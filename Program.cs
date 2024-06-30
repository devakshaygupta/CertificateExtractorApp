using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Microsoft.Identity.Client;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

public class Program
{
    public static async Task Main(string[] args)
    {
        try
        {
            string secretFilePath = args[0];
            string secretValue = File.ReadAllText(secretFilePath).Trim();
            byte[] rawData = Convert.FromBase64String(secretValue);

            // Load the certificate
            X509Certificate2 certificate = new X509Certificate2(rawData);

            DateTimeOffset now = DateTimeOffset.UtcNow;
            DateTimeOffset expires = now.AddMinutes(5);

            long nbfUnixTime = (long)now.UtcDateTime.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
            long expUnixTime = (long)expires.UtcDateTime.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

            Console.WriteLine($"nbf: {nbfUnixTime}");
            Console.WriteLine($"exp: {expUnixTime}");

            // Compute the SHA-1 hash of the DER-encoded certificate
            using (var sha1 = SHA1.Create())
            {
                byte[] certHash = sha1.ComputeHash(certificate.RawData);
                // Base64 URL encode the hash
                string x5t = Convert.ToBase64String(certHash);

                Console.WriteLine($"x5t: {x5t}");
            }

            // Check if the certificate has a private key
            if (certificate.HasPrivateKey)
            {

                byte[] pfxData = certificate.Export(X509ContentType.Pfx);

                File.WriteAllBytes("certificate.pfx", pfxData);

                Console.WriteLine("Certificate saved to certificate.pfx");

                // Extract the private key
                var rsaPrivateKey = certificate.GetRSAPrivateKey();

                if (rsaPrivateKey != null)
                {
                    // Convert the private key to BouncyCastle RSA key parameters
                    var rsaKeyPair = DotNetUtilities.GetRsaKeyPair(rsaPrivateKey);

                    if (rsaKeyPair?.Private is RsaPrivateCrtKeyParameters rsaParams)
                    {
                        // Save the private key to a PEM file
                        using (var sw = new StreamWriter("privateKey.pem"))
                        {
                            var pemWriter = new PemWriter(sw);
                            pemWriter.WriteObject(rsaParams);
                        }

                        Console.WriteLine("Private key saved to privateKey.pem");
                    }
                    else
                    {
                        Console.WriteLine("The private key could not be converted to RsaPrivateCrtKeyParameters.");
                    }
                }
            }
            else
            {
                // Export the certificate to a DER file
                File.WriteAllBytes("certificate.der", certificate.RawData);

                Console.WriteLine("Certificate saved to certificate.der");

                Console.WriteLine("The certificate does not contain a private key.");
            }

            // Extract the public key
            var rsaPublicKey = certificate.GetRSAPublicKey();

            if (rsaPublicKey != null)
            {
                // Convert the public key to BouncyCastle RSA key parameters
                RsaKeyParameters rsaPublicParams = DotNetUtilities.GetRsaPublicKey(rsaPublicKey);

                // Save the public key to a PEM file
                using (var sw = new StreamWriter("publicKey.pem"))
                {
                    var pemWriter = new PemWriter(sw);
                    pemWriter.WriteObject(rsaPublicParams);
                }

                Console.WriteLine("Public key saved to publicKey.pem");
            }
            else
            {
                throw new InvalidOperationException("The certificate does not contain a public key.");
            }

            // Set up the Confidential Client Application
            string? applicationId = Environment.GetEnvironmentVariable("INVENTORY_APPLICATION_ID");
            string? authority = Environment.GetEnvironmentVariable("INVENTORY_APP_AUTHORITY_URL");
            string? applicationScope = Environment.GetEnvironmentVariable("INVENTORY_APP_SCOPE");

            if (applicationId == null || authority == null || applicationScope == null)
            {
                throw new InvalidOperationException("Environment variables for applicationId, authority, or scope are not set.");
            }

            string[] scopes = [applicationScope];

            var app = ConfidentialClientApplicationBuilder.Create(applicationId)
                .WithCertificate(certificate)
                .WithAuthority(new Uri(authority))
                .Build();

            var result = await app.AcquireTokenForClient(scopes)
                .WithSendX5C(true)
                .ExecuteAsync()
                .ConfigureAwait(false);

            // Print the access token and other details
            Console.WriteLine($"Token Type: {result.TokenType}");
            Console.WriteLine($"Expires On: {result.ExpiresOn}");
            Console.WriteLine($"Access Token: {result.AccessToken}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to save public/private key or acquire access token: " + ex);
        }
    }
}