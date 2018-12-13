using System;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Xml.Linq;
using NDesk.Options;
using System.Security.Cryptography;

namespace Xmldsig {
    class Program {
        private static string _currentMode;
        private static string _xmlPath;
        private static string _certPath;
        private static string _password;

        private static void Main(string[] args) {
            try {
                var options = new OptionSet() {
                    { "sign", "Sign certificate", v => _currentMode = "sign" },
                    { "verify", "Verify signature", v => _currentMode = "verify" },
                    { "xmlpath=", "Path to XML file to sign", x => _xmlPath = x },
                    { "certpath=", "Path to PFX certificate", x => _certPath = x },
                    { "password=", "Password for PFX certificate", x => _password = x },
                    { "help", "Show this message and exit", x => { } },
                };
                options.Parse(args);

                if (_currentMode == "sign" && !string.IsNullOrEmpty(_xmlPath) && !string.IsNullOrEmpty(_certPath) && !string.IsNullOrEmpty(_password)) {
                    var doc = XDocument.Load(_xmlPath);

                    var cert = new X509Certificate2(File.ReadAllBytes(_certPath), _password);
                    var xmlDoc = doc.ToXmlDocument();

                    SignXmlDocumentWithCertificate(xmlDoc, cert);

                    File.WriteAllText(_xmlPath, xmlDoc.OuterXml);
                }
                else if (_currentMode == "verify" && !string.IsNullOrEmpty(_xmlPath)) {
                    var isVerified = VerifyXmlFile(_xmlPath);
                    if (isVerified) {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("XML signature is valid");
                        Console.ResetColor();
                    }
                    else {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("XML signature is NOT valid");
                        Console.ResetColor();
                    }
                }
                else {
                    ShowHelp(options);
                }
            }
            catch (Exception ex) {
                Console.WriteLine(ex.Message);
            }
        }

        private static bool VerifyXmlFile(string path) {
            var xmlDocument = XDocument.Load(path).ToXmlDocument();

            xmlDocument.PreserveWhitespace = true;

            var signedXml = new SignedXml(xmlDocument);

            var nodeList = xmlDocument.GetElementsByTagName("Signature", "http://www.w3.org/2000/09/xmldsig#");

            if (nodeList.Count <= 0) {
                throw new CryptographicException("Verification failed: No Signature was found in the document.");
            }

            if (nodeList.Count >= 2) {
                throw new CryptographicException("Verification failed: More that one signature was found for the document.");
            }
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return signedXml.CheckSignature();
        }

        private static void SignXmlDocumentWithCertificate(XmlDocument doc, X509Certificate2 cert) {
            doc.PreserveWhitespace = true;
            var signedXml = new SignedXml(doc);

            signedXml.SigningKey = cert.PrivateKey;

            var reference = new Reference();
            reference.Uri = "";

            var env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            var exc = new XmlDsigExcC14NTransform();
            reference.AddTransform(exc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));

            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            var xmlSig = signedXml.GetXml();

            doc.DocumentElement.AppendChild(doc.ImportNode(xmlSig, true));


            Console.WriteLine("Successfully signed.");
        }

        private static void ShowHelp(OptionSet p) {
            Console.WriteLine("Usage: xmldsig -sign -xmlpath=[XMLPATH] -certpath=[CERTPATH] -password=[PASS]");
            Console.WriteLine("       xmldsig -verify -xmlpath=[XMLPATH]");
            Console.WriteLine();
            Console.WriteLine("Sign/verify XML by xmldsig specification.");
            Console.WriteLine();
            Console.WriteLine("Options:");
            p.WriteOptionDescriptions(Console.Out);
        }
    }
}
