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
    //This sample is the same as the original XML signing sample, 
    //just the signature get a "ds:" prefix, because some system requires
    public class XMLDSSigningSample : ISigningSample
    {
        private X509Certificate2 x509Certificate2;
        private bool c14 = true;
        private bool useIncludedCertificate = true;

        private void SetPrefix(string prefix, XmlNode node)
        {
            node.Prefix = prefix;
            foreach (XmlNode n in node.ChildNodes)
            {
                SetPrefix(prefix, n);
            }
        }

        private void ReplaceSignature(XmlElement signature, string newValue)
        {
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (signature.OwnerDocument == null) throw new ArgumentException("No owner document", nameof(signature));

            XmlNamespaceManager nsm = new XmlNamespaceManager(signature.OwnerDocument.NameTable);
            nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

            XmlNode signatureValue = signature.SelectSingleNode("ds:SignatureValue", nsm);
            if (signatureValue == null)
                throw new Exception("Signature does not contain 'ds:SignatureValue'");

            signatureValue.InnerXml = newValue;
        }

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

            // Add prefix "ds:" to signature
            XmlElement xmlDigitalSignature = signedXml.GetXml();
            SetPrefix("ds", xmlDigitalSignature);

            // Load modified signature back
            signedXml.LoadXml(xmlDigitalSignature);

            // this is workaround for overcoming a bug in the library
            signedXml.SignedInfo.References.Clear();

            // Compute the signature.
            signedXml.ComputeSignature();

            string recomputedSignature = Convert.ToBase64String(signedXml.SignatureValue);

            // Replace value of the signature with recomputed one
            ReplaceSignature(xmlDigitalSignature, recomputedSignature);

            // Get the XML representation of the signature and save 
            // it to an XmlElement object.

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
               document.GetElementsByTagName("ds:Signature")[0];

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
