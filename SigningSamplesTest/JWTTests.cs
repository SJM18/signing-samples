using NUnit.Framework;
using SigningSamples;
using System.IdentityModel.Tokens.Jwt;

namespace SigningSamplesTest
{
    public class JWTTests
    {
        private string pfxPath;

        [SetUp]
        public void Setup()
        {
            pfxPath = "SampleCertificate\\Sample-20221030.pfx";
        }

        [Test]
        public void SignAndVerify()
        {
            JWTSigningSample jwtSigningSample = new JWTSigningSample();

            jwtSigningSample.ReadCertification(pfxPath);

            JwtHeader jwtHeader = new JwtHeader();
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Add("sampleData1", "sampleDataContent1");
            jwtPayload.Add("sampleData2", "sampleDataContent2");
            jwtPayload.Add("sampleData3", "sampleDataContent3");

            var secToken = new JwtSecurityToken(jwtHeader, jwtPayload);
            var handler = new JwtSecurityTokenHandler();

            var unsignedTokenString = handler.WriteToken(secToken);

            Assert.NotNull(unsignedTokenString, "UnSigned token string cannot be null");

            string signedTokenString = jwtSigningSample.Sign(unsignedTokenString);

            Assert.NotNull(signedTokenString, "Signed token string cannot be null");

            Assert.That(jwtSigningSample.Verify(signedTokenString), "JWT Signed string cannot be verify");
        }
    }
}