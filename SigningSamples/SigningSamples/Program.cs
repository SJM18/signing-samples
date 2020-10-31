using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace SigningSamples
{
    class Program
    {
        static void Main(string[] args)
        {
            #region JWT case
            JWTSigningSample jwtSigningSample = new JWTSigningSample();

            jwtSigningSample.ReadCertification();

            JwtHeader jwtHeader = new JwtHeader();
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Add("sampleData1", "sampleDataContent1");
            jwtPayload.Add("sampleData2", "sampleDataContent2");
            jwtPayload.Add("sampleData3", "sampleDataContent3");

            var secToken = new JwtSecurityToken(jwtHeader, jwtPayload);
            var handler = new JwtSecurityTokenHandler();

            var unsignedTokenString = handler.WriteToken(secToken);

            string signedTokenString = jwtSigningSample.Sign(unsignedTokenString);

            if (jwtSigningSample.Verify(signedTokenString))
            {
                Console.WriteLine("JWT verified successfully");
            }

            #endregion

            #region XML case

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

            XMLSigningSample xmlSigningSample = new XMLSigningSample();
            xmlSigningSample.ReadCertification();

            string signedXml = xmlSigningSample.Sign(sb.ToString());

            if (xmlSigningSample.Verify(signedXml))
            {
                Console.WriteLine("XML verified successfully");
            }

            #endregion


            #region XML with DS prefix case

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
            xmldsSigningSample.ReadCertification();

            string signedDsXml = xmldsSigningSample.Sign(sbds.ToString());

            if (xmldsSigningSample.Verify(signedDsXml))
            {
                Console.WriteLine("XML with DS prefix verified successfully");
            }

            #endregion
        }
    }
}
