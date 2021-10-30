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
    public class XMLDSTests
    {
        private string pfxPath;

        [SetUp]
        public void Setup()
        {
            pfxPath = Path.Combine("SampleCertificate", "Sample-20221030.pfx");
        }

        [Test]
        public void SignAdnVerify()
        {
            StringBuilder sbds = new StringBuilder();

            sbds.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sbds.Append("<SigningSampleDsXml>");
            sbds.Append("  <SampleNode>");
            sbds.Append("    <Name>Foo</Name>");
            sbds.Append("    <Type>XML</Type>");
            sbds.Append("    <LuckyNumbers>12341234243</LuckyNumbers>");
            sbds.Append("    <SomeImportantDate>1988-09-18T03:00:00.433+01:00</SomeImportantDate>");
            sbds.Append("  </SampleNode>");
            sbds.Append("</SigningSampleDsXml>");

            XMLDSSigningSample xmldsSigningSample = new XMLDSSigningSample();
            xmldsSigningSample.ReadCertification(pfxPath);

            string signedDsXml = xmldsSigningSample.Sign(sbds.ToString());

            Assert.NotNull(signedDsXml, "Signed XML (DS) string cannot be null");

            Assert.That(xmldsSigningSample.Verify(signedDsXml), "XML (DS) Signed string cannot be verify");
        }
    }
}
