using System;
using System.IdentityModel.Tokens.Jwt;

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

            if(jwtSigningSample.Verify(signedTokenString))
            {
                Console.WriteLine("JWT Verified successfully");
            }

            #endregion

        }
    }
}
