using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Microsoft.Data.SqlClient;
using Org.BouncyCastle;

using CertificateRequest = System.Security.Cryptography.X509Certificates.CertificateRequest;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Security;

namespace PdfDigitalSignature
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Aplicacion firma digital PDF");

            // Prompt for the PDF file path
        Console.WriteLine("Ingresa la ruta del archivo: ");
              string pdfFilePath = Console.ReadLine();

      
           // string pdfFilePath = @"C:\Users\pc\Desktop\NET.pdf";

            // Generate private and public keys
            RSA privateKey = GeneratePrivateKey();
            RSAParameters privateKeyParams = privateKey.ExportParameters(true);
            RSA publicKey = CreatePublicKeyFromPrivateKey(privateKeyParams);

        
              static RSA CreatePublicKeyFromPrivateKey(RSAParameters privateKeyParams)
            {
                RSA publicKey = RSA.Create();
                publicKey.ImportParameters(new RSAParameters
                {
                    Modulus = privateKeyParams.Modulus,
                    Exponent = privateKeyParams.Exponent
                });
                return publicKey;
            }

            // Save private key to a protected file
            string privateKeyFile = @"C:\\Users\\pc\\source\\repos\\SignedPDF File/archivo.pem";
            SavePrivateKey(privateKey, privateKeyFile);

            // Save public key to a file
            string publicKeyFile = @"C:\\Users\\pc\\source\\repos\\SignedPDF File/archivo.pub";
            SavePublicKey(publicKey, publicKeyFile);

            // Load the PDF document
            var pdfReader = new PdfReader(pdfFilePath);
            var signedPdfFilePath = Path.ChangeExtension(pdfFilePath, "_firmado.pdf");

            // Create a new PDF document
            using (var stream = new FileStream(signedPdfFilePath, FileMode.Create))
            using (var pdfDocument = new Document())
            using (var pdfWriter = PdfWriter.GetInstance(pdfDocument, stream))
            {
                // Open the PDF document
                pdfDocument.Open();

            /*    // Sign the PDF document
                var nombre = "sergio"; // Replace with your actual name
                var apellido = "vasquez"; // Replace with your actual surname
                var email = "your.email@example.com"; // Replace with your actual email*/


                 Console.WriteLine("Cual es tu nombre: ");
                 var nombre = Console.ReadLine();

                 Console.WriteLine("Cual es tu apellido: ");
                 var apellido = Console.ReadLine();

                 Console.WriteLine("Cual es tu email: ");
                 var email = Console.ReadLine();



                var fullName = nombre + " " + apellido;

                // Call the SignPdfCert method
                SignPdfCert(pdfFilePath, signedPdfFilePath, "Digital Signature", "Location", privateKeyFile, "certPassword", "36", "36", "144", "144", 10);

                Console.WriteLine("PDF file signed successfully!");

                // Store signer information in the database
                StoreInDatabase($"{nombre} {apellido}", email, pdfFilePath, signedPdfFilePath);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static RSA GeneratePrivateKey()
        {
            RSA rsa = RSA.Create();
            rsa.KeySize = 2048; // Key size (adjust as needed)
            return rsa;
        }

        static void SavePrivateKey(RSA privateKey, string privateKeyFile)
        {
            CspParameters cspParams = new CspParameters();
            cspParams.KeyContainerName = "KeyContainerName"; // Choose a key container name
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(cspParams);
            rsaCsp.ImportParameters(privateKey.ExportParameters(true));

            // Save the private key to a protected file
            File.WriteAllText(privateKeyFile, rsaCsp.ToXmlString(true));
        }

        static void SavePublicKey(RSA publicKey, string publicKeyFile)
        {
            // Export the public key
            File.WriteAllText(publicKeyFile, publicKey.ToXmlString(false));
        }

        static void SignPdfCert(string src, string dest, string reason, string location, string privateKeyFile, string certPassword, string llx, string lly, string urx, string ury, int fontSize)
        {
            // Load the private key from the protected file
            string privateKeyXml = File.ReadAllText(privateKeyFile);
            RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider();
            rsaCsp.FromXmlString(privateKeyXml);
            RSA privateKey = rsaCsp;

            // Convert the private key to BouncyCastle format
            AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(privateKey);

            // Create a self-signed X.509 certificate using the private key
            X509Certificate2 certificate = GenerateSelfSignedCertificate(privateKey);

            // Convert the X509Certificate2 to Org.BouncyCastle.X509.X509Certificate
            X509CertificateParser parser = new X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { parser.ReadCertificate(certificate.RawData) };

            IExternalSignature externalSignature = new PrivateKeySignature(keyPair.Private, DigestAlgorithms.SHA512);
            PdfReader pdfReader = new PdfReader(src);
            FileStream signedPdf = new FileStream(dest, FileMode.Create);
            PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, signedPdf, '\0');
            PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
            signatureAppearance.Reason = reason;
            signatureAppearance.Location = location;
            BaseFont bf = BaseFont.CreateFont();
            signatureAppearance.Layer2Font = new Font(bf, fontSize);
            signatureAppearance.SetVisibleSignature(new Rectangle(float.Parse(llx), float.Parse(lly), float.Parse(urx), float.Parse(ury)), 1, "sig");

            // Sign the PDF using the private key and certificate chain
            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
        }


        static X509Certificate2 GenerateSelfSignedCertificate(RSA privateKey)
        {
            // Generate a self-signed X.509 certificate
            CertificateRequest request = new CertificateRequest(
                new X500DistinguishedName("CN=Digital Signature"),
                privateKey,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);

            // Set certificate attributes (adjust as needed)
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
            request.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));

            // Create a self-signed X.509 certificate
            X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddDays(365));

            return certificate;
        }

        static void StoreInDatabase(string fullName, string email, string originalFilePath, string signedFilePath)
        {
            string connectionString = "Server=DESKTOP-GN6RBDV;Database=ESCAFANDRA;" +
                "Integrated Security=True;TrustServerCertificate=True";

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                string query = "INSERT INTO Signers (FullName, Email, OriginalFilePath, SignedFilePath) " +
                               "VALUES (@FullName, @Email, @OriginalFilePath, @SignedFilePath)";

                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@FullName", fullName);
                command.Parameters.AddWithValue("@Email", email);
                command.Parameters.AddWithValue("@OriginalFilePath", originalFilePath);
                command.Parameters.AddWithValue("@SignedFilePath", signedFilePath);

                connection.Open();
                command.ExecuteNonQuery();
            }
        }
    }
}
