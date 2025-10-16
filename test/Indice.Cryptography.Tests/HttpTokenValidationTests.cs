using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Indice.Cryptography.Tokens.HttpMessageSigning;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Indice.Cryptography.Tests;

public class HttpTokenValidationTests
{
    private const string ValidAudience = "identity.indice.gr";
    private const string ValidIssuer = "www.indice.gr";
    private const string ValidSubject = "GR-BOG-800000005";
    private const string TEST_X509_PublicKey_2048 = "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";
    private const string TEST_RSA_PrivateKey_256 =
        @"-----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEAqz0wUEKPdxlYKYBQp0TyInlUPuWVH6J1MkLOn20I/gFyu387
            CDiP3wTnK4Kz382H7vfzHtPyo5WnGKN2RRZF0HXVSEIaCfcYKOsKYzh16d0x7wuJ
            RSPUV9AqdlNCC5wWYF+NM4KFFlOym6xOYbcQI/KWP9n2ToNC/vDJaXaQ0tpzAP7m
            EuULS5d5OP2/UhkiuJPe1I2e6kXSUki6EGCAc+tckdaZMJ1ctebsRS7FaWDfpCeX
            9cILQtmLtLCQuRtFBB/ZfjJWmt7QzpjU3PTNXXl4MwI+z3sJGE2nsfORT9bd2LCu
            p7yFAGIDXqcNKE3We6PdsCjOLMHtWSwGOt6XJQIDAQABAoIBAApsNgWcl4jjRQd5
            pO8Zdjd89RDC/pmnVMTTZio0A8kaI3agHuK4NqGXdc6jLPmhU/XKp8Snl+w3Dq2k
            PW2lFmjC01GLnHQg0xqie8ZgSGUMrp5jMF7B+InDxOHg3XNBc+c3yatp9VnPjF6H
            VVoDP3tAp76JMMHEoY5M76V4rwX2Zlg9GPOaVbANEvuetsvCxI7zRj10XkFccL4T
            4s+RRXM5jGu1HHzMsdmYE5cnnfXMVPHPhR0YJBTOD8nUz9GZp1aq39KfRW4yN+lO
            PtcHteOE49Mi4kFi0RM7emLgHNCASp9vPa1okk8Lf4TqrzUNcc2D5IpEwyJJUxW1
            WtxJjD0CgYEAwLd9Fvtv9LGOSAiVT7gccEjwMNY3kJaE44xVlMYLLJNuB2E4Y4VF
            gfTeqTnkBjvS7WMhwJqRiiEx4zmWFnlqdgRC7HDOOaewHZmNkd03qpFaxccD3fpi
            kVdOCEDr51w2+wvBvhlXwBzcL8+7E0EXkQegfo3RBax3kx6uxPL2V38CgYEA43gy
            /O7QtrKAn1XoDmhoG6OyfgHDPSES4SJzssU52+YzjXTNsA9BGCcDb9MPYExnldSp
            wLoGpmvl3wmqQVyrCWEkEPWTV/ZZf7Q7UhARiICZMBPl5uE4Zejhe/5Qhip9GCYV
            T14NgdlUwmWDz06O+PUXdI8J2NzujmbfBgE5A1sCgYBODIH+wsouwZIsHj3KUXhD
            CWctgDR0vGEJfxZR8HsqDHNtTbR2qcziuvdKdgWheK0OMy3CQVdcJ+F6cyIT7Axv
            y34HIBCFTSKIel3Zi0w2KjQnEVjBl9w/nKofsZtY0gH6XmKSyNS/G3EZc/oB7ETN
            GdeoKWtT7utmi/CgFv4ppQKBgFvc+CKDw9B0qFMw22WuLpUy9+vBhHqUd85qHnWN
            Bv/SqPEwwbyffHdnkhDAGQ6X7KFq4B9QQU1Gd/AqNBLvfLdt/qXGt3mnqJ9VRzut
            95a78KGk94zVWfR2J1Hu89ArKpftEWAbKLNO9NcJLkEzhbPvL0jIV364QrNJwjnn
            loHPAoGBAKJ8sTZ5mIj2npyRYdWRcx1s5qsVw3Tl2Z4ZuZMePNOhJbCVUPk3a6ML
            CQhq1wf1CMW5DbnZfzlpUEhOjc1nOvFYRlTiUde0sViffUdH9lapEdsu62ufV+GO
            cIrtF3LFmXhdwJUAkgTLTZt7RYi/KKRCL0om7SEsM/QOjbWkrRl+
            -----END RSA PRIVATE KEY-----";

    [Fact]
    public void HttpTokenValidationTest_RSA_X509() {
        var privateKey = TEST_RSA_PrivateKey_256.ReadAsRSAKey();
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(TEST_X509_PublicKey_2048));
        var securityKey = new RsaSecurityKey(privateKey) {
            KeyId = cert.GetSubjectKeyIdentifier()
        };
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature);
        var payload = @"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}";
        var requestId = "ed67e7c4-9985-45a9-8f1c-7ce7d9c007fe";
        var requestDate = DateTime.UtcNow;
        var requestTarget = new HttpRequestTarget("POST", "/payment");
        var token = new HttpSignatureSecurityToken(signingCredentials, Encoding.UTF8.GetBytes(payload), requestId, requestDate, requestTarget);
        var digestHeader = token.Digest.ToString();
        var signatureHeader = token.Signature.ToString();
        var validationKey = new X509SecurityKey(cert);
        var validatedToken = new HttpSignatureSecurityToken(digestHeader, signatureHeader);
        var disgestIsValid = validatedToken.Digest.Validate(Encoding.UTF8.GetBytes(payload));
        var signatureIsValid = validatedToken.Signature.Validate(validationKey, digestHeader, requestId, requestDate, requestTarget);
        Assert.True(disgestIsValid);
        Assert.True(signatureIsValid);
    }

    [Fact]
    public void HttpTokenValidationTest_HMAC() {
        var secret = "simple-key";
        var securityKey = JsonWebKeyConverter.ConvertFromSymmetricSecurityKey(
            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)) {
                KeyId = "my-symmetric-key-id"
            }
        );

        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var payload = @"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}";
        var requestId = "ed67e7c4-9985-45a9-8f1c-7ce7d9c007fe";
        var requestDate = DateTime.UtcNow;
        var requestTarget = new HttpRequestTarget("POST", "/payment");
        var token = new HttpSignatureSecurityToken(signingCredentials, Encoding.UTF8.GetBytes(payload), requestId, requestDate, requestTarget);
        var digestHeader = token.Digest.ToString();
        var signatureHeader = token.Signature.ToString();

        var validationKey = securityKey; // this is symmetric
        var validatedToken = new HttpSignatureSecurityToken(digestHeader, signatureHeader);
        var disgestIsValid = validatedToken.Digest.Validate(Encoding.UTF8.GetBytes(payload));
        var signatureIsValid = validatedToken.Signature.Validate(validationKey, digestHeader, requestId, requestDate, requestTarget);
        Assert.True(disgestIsValid);
        Assert.True(signatureIsValid);
    }

    [Fact]
    public void HttpTokenValidationTest_RSA_JWK() {
        var privateKey = TEST_RSA_PrivateKey_256.ReadAsRSAKey();
        var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(TEST_X509_PublicKey_2048));
        var securityKey = new RsaSecurityKey(privateKey) {
            KeyId = cert.GetSubjectKeyIdentifier()
        };
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256Signature);
        var payload = @"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}";
        var requestId = "ed67e7c4-9985-45a9-8f1c-7ce7d9c007fe";
        var requestDate = DateTime.UtcNow;
        var requestTarget = new HttpRequestTarget("POST", "/payment");
        var token = new HttpSignatureSecurityToken(signingCredentials, Encoding.UTF8.GetBytes(payload), requestId, requestDate, requestTarget);
        var digestHeader = token.Digest.ToString();
        var signatureHeader = token.Signature.ToString();

        // Get the public key from the private key in JWK format (as it would be received from identity server)
        var publicKey = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(TEST_X509_PublicKey_2048));
        var rsa = publicKey.GetRSAPublicKey();        
        var validationKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(rsa) {
            KeyId = securityKey.KeyId
        });

        var validatedToken = new HttpSignatureSecurityToken(digestHeader, signatureHeader);
        var disgestIsValid = validatedToken.Digest.Validate(Encoding.UTF8.GetBytes(payload));
        var signatureIsValid = validatedToken.Signature.Validate(validationKey, digestHeader, requestId, requestDate, requestTarget);
        Assert.True(disgestIsValid);
        Assert.True(signatureIsValid);
    }

    [Fact]
    public void HttpTokenValidationTest_RSA_JWK_BOTH() {
        var privateKey = RSA.Create();
        privateKey.ImportFromPem(TEST_RSA_PrivateKey_256.ToCharArray());
        var singingKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(privateKey) {
            KeyId = "my-key-id"
        });

        var signingCredentials = new SigningCredentials(singingKey, SecurityAlgorithms.RsaSha256Signature);
        var payload = @"{""amount"":123.9,""date"":""2019-06-21T12:05:40.111Z""}";
        var requestId = "ed67e7c4-9985-45a9-8f1c-7ce7d9c007fe";
        var requestDate = DateTime.UtcNow;
        var requestTarget = new HttpRequestTarget("POST", "/payment");
        var token = new HttpSignatureSecurityToken(signingCredentials, Encoding.UTF8.GetBytes(payload), requestId, requestDate, requestTarget);
        var digestHeader = token.Digest.ToString();
        var signatureHeader = token.Signature.ToString();

        var publicKey = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(TEST_X509_PublicKey_2048));
        var validationKey = JsonWebKeyConverter.ConvertFromX509SecurityKey(new X509SecurityKey(publicKey) {
            KeyId = singingKey.KeyId
        });

        var validatedToken = new HttpSignatureSecurityToken(digestHeader, signatureHeader);
        var disgestIsValid = validatedToken.Digest.Validate(Encoding.UTF8.GetBytes(payload));
        var signatureIsValid = validatedToken.Signature.Validate(validationKey, digestHeader, requestId, requestDate, requestTarget);
        Assert.True(disgestIsValid);
        Assert.True(signatureIsValid);
    }
}
