using NUnit.Framework;
using SigningSamples;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SigningSamplesTest
{

    public class XMLTests
    {
        private string pfxPath;

        [SetUp]
        public void Setup()
        {
            pfxPath = Path.Combine("SampleCertificate", "Sample-20221030.pfx");
        }

        [Test]
        public void SignAndVerify()
        {
            StringBuilder sb = new StringBuilder();

            sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.Append("<SigningSampleXml>");
            sb.Append("  <SampleNode>");
            sb.Append("    <Name>Foo</Name>");
            sb.Append("    <Type>XML</Type>");
            sb.Append("    <LuckyNumbers>12341234243</LuckyNumbers>");
            sb.Append("    <SomeImportantDate>1988-09-18T03:00:00.433+01:00</SomeImportantDate>");
            sb.Append("  </SampleNode>");
            sb.Append("</SigningSampleXml>");

            Assert.NotNull(sb.ToString(), "UnSigned XML string cannot be null");

            XMLSigningSample xmlSigningSample = new XMLSigningSample();
            xmlSigningSample.ReadCertification(pfxPath);

            string signedXml = xmlSigningSample.Sign(sb.ToString());

            Assert.NotNull(signedXml, "Signed XML string cannot be null");

            Assert.That(xmlSigningSample.Verify(signedXml), "XML Signed string cannot be verify");
        }
    }
}
