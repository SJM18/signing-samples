using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Serialization;
using Newtonsoft.Json;
using NUnit.Framework;
using SigningSamples;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace SigningSamplesTest
{
    public class JWTTests
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

            Assert.That(jwtSigningSample.Verify(signedTokenString), "JWT Signed string unable to verify");
        }

        [Test]
        public void JWKSTest()
        {
            //Sign JWT
            JWTSigningSample jwtSigningSample = new JWTSigningSample();

            jwtSigningSample.ReadCertification(pfxPath);

            JwtHeader jwtHeader = new JwtHeader();
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Add("sampleData1", "sampleDataContent1");
            jwtPayload.Add("sampleData2", "sampleDataContent2");
            jwtPayload.Add("sampleData3", "sampleDataContent3");
            jwtPayload.Add("sampleData4", "sampleDataContent4");

            var secToken = new JwtSecurityToken(jwtHeader, jwtPayload);
            var handler = new JwtSecurityTokenHandler();

            var unsignedTokenString = handler.WriteToken(secToken);

            Assert.NotNull(unsignedTokenString, "UnSigned token string cannot be null");

            string signedTokenString = jwtSigningSample.Sign(unsignedTokenString);

            Assert.NotNull(signedTokenString, "Signed token string cannot be null");

            //Create JWKS json
            X509Certificate2 signingCert = new X509Certificate2(pfxPath, "sample", X509KeyStorageFlags.MachineKeySet);
            var certBytes = signingCert.Export(X509ContentType.Cert);
            var certA = new X509Certificate2(certBytes);

            RSA key = signingCert.PublicKey.Key as RSA;
            RSAParameters parameters = key.ExportParameters(false);

            byte[] exponent = parameters.Exponent;
            byte[] modulus = parameters.Modulus;
            var e = Base64UrlEncoder.Encode(exponent);
            var n = Base64UrlEncoder.Encode(modulus);

            X509SecurityKey x509SecurityKey = new X509SecurityKey(certA);
            JsonWebKey jsonWebKey = JsonWebKeyConverter.ConvertFromX509SecurityKey(x509SecurityKey);
            jsonWebKey.E = e;
            jsonWebKey.N = n;
            jsonWebKey.Use = "sig";

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();
            jsonWebKeySet.Keys.Add(jsonWebKey);

            var serializerSettings = new JsonSerializerSettings();
            serializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
            serializerSettings.NullValueHandling = NullValueHandling.Ignore;

            var jwksJSONResult = JsonConvert.SerializeObject(jsonWebKeySet, serializerSettings);

            //Create public certification from JWKS
            JsonWebKeySet jsonWebKeySetFromJson = new JsonWebKeySet(jwksJSONResult);

            var secKey = jsonWebKeySetFromJson.Keys.FirstOrDefault();

            Assert.NotNull("Parsed JWKS string cannot be null");

            JWTSigningSample jwksSigningSample = new JWTSigningSample();

            jwksSigningSample.SetSecurityKey(secKey);

            Assert.That(jwksSigningSample.Verify(signedTokenString), "JWT Signed string unable to verify");
        }
    }
}