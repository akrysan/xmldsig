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
        private static string _xmlPath;
        private static string _certPath;
        private static string _password;

        private static string ReadOptions(string[] args) {
            var currentParameter = "";
            var options = new OptionSet() {
                { "sign", "Provide the path to xml file,path to certificate,password", v => currentParameter = "sign" },
                { "verify", "Provide the path to xml file,path to certificate,password", v => currentParameter = "verify" },
                { "xmlPath=","",x => _xmlPath = x },
                { "certPath=","",x => _certPath = x },
                { "password=","",x => _password = x },
                
            };
            options.Parse(args);
            return currentParameter;
        }
        
        private static void Main(string[] args) {
            try {
                var key = ReadOptions(args);
                if (key == "sign" && !string.IsNullOrEmpty(_xmlPath) && !string.IsNullOrEmpty(_certPath) && !string.IsNullOrEmpty(_password)) {
                    var doc = XDocument.Load(_xmlPath);

                    var cert = new X509Certificate2(File.ReadAllBytes(_certPath), _password);
                    var xmlDoc = doc.ToXmlDocument();

                    SignXmlDocumentWithCertificate(xmlDoc, cert);

                    File.WriteAllText(_xmlPath, xmlDoc.OuterXml);
                }
                if (key == "verify" && !string.IsNullOrEmpty(_xmlPath)) {
                    var isVerified = VerifyXmlFile(_xmlPath);
                    if (isVerified) {
                        Console.WriteLine("XML is Verified");
                    }
                    else {
                        Console.WriteLine("XML is not Verified");
                    }
                }
            }
            catch (Exception e) {
                Console.WriteLine(e.Message);
            }
        }

        public static bool VerifyXmlFile(string path) {
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
        public static void SignXmlDocumentWithCertificate(XmlDocument doc, X509Certificate2 cert) {
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
    }
}
