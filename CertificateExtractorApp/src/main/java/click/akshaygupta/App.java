package click.akshaygupta;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
//import org.bouncycastle.pkcs.jcajce.JcaPKCS8Generator;
import org.bouncycastle.util.io.pem.PemObject;
import com.microsoft.aad.msal4j.*;

public class App {
    public static void main(String[] args) {
        try {
            String secretFilePath = args[0];
            String secretValue = new String(Files.readAllBytes(Paths.get(secretFilePath))).trim();
            byte[] rawData = Base64.getDecoder().decode(secretValue);

            // Load the certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(rawData));

            long now = System.currentTimeMillis() / 1000;
            long expires = now + 300;

            System.out.println("nbf: " + now);
            System.out.println("exp: " + expires);

            // Compute the SHA-1 hash of the DER-encoded certificate
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            byte[] certHash = sha1.digest(certificate.getEncoded());
            String x5t = Base64.getUrlEncoder().withoutPadding().encodeToString(certHash);

            System.out.println("x5t: " + x5t);

            // Check if the certificate has a private key
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new ByteArrayInputStream(rawData), null);

            String alias = keystore.aliases().nextElement();
            Key key = keystore.getKey(alias, null);

            if (key instanceof RSAPrivateKey) {
                // Save the certificate to a PFX file
                try (FileOutputStream fos = new FileOutputStream("certificate.pfx")) {
                    keystore.store(fos, "".toCharArray());
                }
                System.out.println("Certificate saved to certificate.pfx");

                // Convert the private key to BouncyCastle RSA key parameters
                PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(key.getEncoded());
                try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter("privateKey.pem"))) {
                    pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKeyInfo.getEncoded()));
                }
                System.out.println("Private key saved to privateKey.pem");
            } else {
                // Export the certificate to a DER file
                try (FileOutputStream fos = new FileOutputStream("certificate.der")) {
                    fos.write(certificate.getEncoded());
                }
                System.out.println("Certificate saved to certificate.der");
                System.out.println("The certificate does not contain a private key.");
            }

            // Extract the public key
            PublicKey publicKey = certificate.getPublicKey();
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter("publicKey.pem"))) {
                pemWriter.writeObject(publicKey);
            }
            System.out.println("Public key saved to publicKey.pem");

            // Set up the Confidential Client Application
            String applicationId = System.getenv("MICROSOFT_APPLICATION_ID");
            String authority = System.getenv("MICROSOFT_AUTHORITY_URL");
            String scope = System.getenv("MICROSOFT_SCOPE");

            if (applicationId == null || authority == null || scope == null) {
                throw new IllegalStateException(
                        "Environment variables for applicationId, authority, or scope are not set.");
            }

            /*
            ConfidentialClientApplication app = ConfidentialClientApplication
                    .builder(applicationId,
                            ClientCredentialFactory.createFromCertificate(certificate, (RSAPrivateKey) key))
                    .authority(authority)
                    .build();

            IAuthenticationResult result = app
                    .acquireToken(ClientCredentialParameters.builder(Collections.singleton(scope)).build()).get();

            // Print the access token and other details
            System.out.println("Expires On: " + result.expiresOnDate());
            System.out.println("Access Token: " + result.accessToken());
            */
        } catch (Exception ex) {
            System.out.println("Failed to save public/private key or acquire access token: " + ex.getMessage());
        }
    }
}
