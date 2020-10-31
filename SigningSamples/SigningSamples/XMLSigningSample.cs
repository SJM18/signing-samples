using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace SigningSamples
{
    public class XMLSigningSample : ISigningSample
    {
        private X509Certificate2 x509Certificate2;
        private bool c14 = true;
        private bool useIncludedCertificate = true;

        public void ReadCertification()
        {
            var path = Path.Combine(Directory.GetCurrentDirectory(), "SampleCertificate\\Sample.pfx");

            this.x509Certificate2 = new X509Certificate2(path, "sample", X509KeyStorageFlags.MachineKeySet);
        }

        public string Sign(string input)
        {
            XmlDocument document = new XmlDocument();
            document.LoadXml(input);

            SignedXml signedXml = new SignedXml(document);

            //CspParameters cspParams = new CspParameters(24) { KeyContainerName = "XML_DSIG_RSA_KEY" };
            //RSACryptoServiceProvider key = new RSACryptoServiceProvider(cspParams);
            //key.FromXmlString(manager.CertificatePfx.PrivateKey.ToXmlString(true));

            AsymmetricAlgorithm privateRSAKey = x509Certificate2.GetRSAPrivateKey();

            signedXml.SigningKey = privateRSAKey;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA1Url;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.            
            XmlDsigEnvelopedSignatureTransform env =
               new XmlDsigEnvelopedSignatureTransform(true);
            reference.AddTransform(env);

            if (c14)
            {
                XmlDsigC14NTransform c14t = new XmlDsigC14NTransform();
                reference.AddTransform(c14t);
            }

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            KeyInfoX509Data keyInfoData = new KeyInfoX509Data(x509Certificate2);
            keyInfo.AddClause(keyInfoData);
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            document.DocumentElement.AppendChild(
                document.ImportNode(xmlDigitalSignature, true));

            return document.OuterXml;
        }

        public bool Verify(string signedInput)
        {
            // load the document to be verified
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            document.LoadXml(signedInput);

            SignedXml signedXml = new SignedXml(document);

            // load the first <signature> node and load the signature  
            XmlNode MessageSignatureNode =
               document.GetElementsByTagName("Signature")[0];

            signedXml.LoadXml((XmlElement)MessageSignatureNode);

            X509Certificate2 certificate = null;
            if (useIncludedCertificate)
            {

                // get the cert from the signature
                foreach (KeyInfoClause clause in signedXml.KeyInfo)
                {
                    if (clause is KeyInfoX509Data)
                    {
                        if (((KeyInfoX509Data)clause).Certificates.Count > 0)
                        {
                            certificate =
                            (X509Certificate2)((KeyInfoX509Data)clause).Certificates[0];
                        }
                    }
                }

            }
            else
            {
                certificate = x509Certificate2;
            }

            // check the signature and return the result.
            return signedXml.CheckSignature(certificate, true);
        }
    }
}
