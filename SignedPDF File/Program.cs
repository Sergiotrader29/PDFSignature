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
using System.Security.Claims;
using Org.BouncyCastle.Crypto.Tls;
using CertificateRequest = System.Security.Cryptography.X509Certificates.CertificateRequest;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using Org.BouncyCastle.Asn1.X509;
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

            // Load the PDF document
            var pdfReader = new PdfReader(pdfFilePath);
            var signedPdfFilePath = pdfFilePath.Insert(pdfFilePath.LastIndexOf('.'), "_firmado.pdf");

            // Create a new PDF document
            using (var stream = new FileStream(signedPdfFilePath, FileMode.Create))
            using (var pdfDocument = new Document())
            using (var pdfWriter = PdfWriter.GetInstance(pdfDocument, stream))
            {
                // Open the PDF document
                pdfDocument.Open();

                Console.WriteLine("Cual es tu nombre: ");
                var nombre = Console.ReadLine();

                Console.WriteLine("Cual es tu apellido: ");
                var apellido = Console.ReadLine();

                Console.WriteLine("Cual es tu email: ");
                var email = Console.ReadLine();

                var fullName = nombre + " " + apellido;


                // Call the SignPdfCert method
                SignPdfCert(pdfFilePath, signedPdfFilePath, "Digital Signature", "Location", "certPassword", "certFile", "36", "36", "144", "144", 10);

                Console.WriteLine("PDF file signed successfully!");

                // Store signer information in the database
                StoreInDatabase($"{nombre} {apellido}", email, pdfFilePath, signedPdfFilePath);
            }

            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        static void SignPdfCert(string src, string dest, string reason, string location, string certPassword, string certFile, string llx, string lly, string urx, string ury, int fontSize)
        {
            Pkcs12Store p12ks = new Pkcs12Store();
            FileStream fs = new FileStream(certFile, FileMode.Open);
            p12ks.Load(fs, certPassword.ToCharArray());
            string alias = "";
            foreach (string al in p12ks.Aliases)
            {
                if (p12ks.IsKeyEntry(al) && p12ks.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }
            }
            AsymmetricKeyParameter pk = p12ks.GetKey(alias).Key;
            ICollection<X509Certificate> chain = new List<X509Certificate>();
            foreach (X509CertificateEntry entry in p12ks.GetCertificateChain(alias))
            {
                chain.Add(entry.Certificate);
            }

            fs.Close();

            IExternalSignature externalSignature = new PrivateKeySignature(pk, DigestAlgorithms.SHA512);
            PdfReader pdfReader = new PdfReader(src);
            FileStream signedPdf = new FileStream(dest, FileMode.Create);
            PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, signedPdf, '\0');
            PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
            signatureAppearance.Reason = reason;
            signatureAppearance.Location = location;
            BaseFont bf = BaseFont.CreateFont();
            signatureAppearance.Layer2Font = new Font(bf, fontSize);
            signatureAppearance.SetVisibleSignature(new Rectangle(float.Parse(llx), float.Parse(lly), float.Parse(urx), float.Parse(ury)), 1, "sig");

            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
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




