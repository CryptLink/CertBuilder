using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using static CryptLink.SigningFramework.Hash;

namespace CryptLink.CertBuilderTests {

    [TestFixture]
    public class TestX509CertBuilder {

        [Test]
        public void X509CertBuilding() {

            var ca1 = new CertBuilder { SubjectName = "CN=Test CA1", KeyStrength = 1024 }.BuildX509();
            Assert.True(ca1.HasPrivateKey);
            Assert.True(Utility.VerifyCert(ca1, true, X509RevocationMode.NoCheck, null), "CA1 is valid (AllowUnknownCertificateAuthority = true)");

            var intermediate1 = new CertBuilder { SubjectName = "CN=Intermediate 1", Issuer = ca1, KeyStrength = 1024}.BuildX509();
            Assert.False(Utility.VerifyCert(intermediate1, false, X509RevocationMode.NoCheck, null), "Intermediate 1 is not valid when CA not provided, and AllowUnknownCA is false");
            Assert.True(Utility.VerifyCert(intermediate1, false, X509RevocationMode.NoCheck, ca1), "Intermediate 1 is valid with: CA1");

            var intermediate2 = new CertBuilder { SubjectName = "CN=Intermediate 2", Issuer = intermediate1, KeyStrength = 1024}.BuildX509();
            Assert.True(Utility.VerifyCert(intermediate2, false, X509RevocationMode.NoCheck, ca1, intermediate1), "Intermediate 2 is valid with: CA1.Intermediate1");

            var cert1 = new CertBuilder { SubjectName = "CN=Test 1", Issuer = intermediate1, KeyStrength = 1024 }.BuildX509();
            Assert.True(Utility.VerifyCert(cert1, false, X509RevocationMode.NoCheck, ca1, intermediate1), "Cert 1 is valid with: CA1.intermediate1");
            Assert.False(Utility.VerifyCert(cert1, false, X509RevocationMode.NoCheck, ca1, intermediate2), "Cert 1 is NOT valid checked against intermediate 2");

            var cert2 = new CertBuilder { SubjectName = "CN=Test 2", Issuer = intermediate2, KeyStrength = 1024 }.BuildX509();
            Assert.True(Utility.VerifyCert(cert2, false, X509RevocationMode.NoCheck, ca1, intermediate1, intermediate2), "Cert 2 is valid with: CA1.intermediate1.intermediate2");

            var cert3 = new CertBuilder { SubjectName = "CN=Test 3", Issuer = cert2, KeyStrength = 1024 }.BuildX509();
            Assert.True(Utility.VerifyCert(cert3, false, X509RevocationMode.NoCheck, ca1, intermediate1, intermediate2, cert2), "Cert 3 is valid with: CA1.intermediate1.intermediate2.Cert2");

            var ca2 = new CertBuilder { SubjectName = "CN=Test CA2", KeyStrength = 1024 }.BuildX509();
            Assert.True(Utility.VerifyCert(ca2, true, X509RevocationMode.NoCheck, null), "CA2 is valid (AllowUnknownCertificateAuthority = true)");

            Assert.False(Utility.VerifyCert(intermediate1, false, X509RevocationMode.NoCheck, ca2), "Intermediate 1A is NOT valid and checked against CA2");

            var invalidCert3 = new CertBuilder {
                SubjectName = "CN=Invalid 1",
                KeyStrength = 1024
            }.BuildX509();

            Assert.False(Utility.VerifyCert(invalidCert3, false, X509RevocationMode.NoCheck, ca2), "Cert 3 is NOT valid when checked against CA2");

            var invalidCert4 = new CertBuilder {
                SubjectName = "CN=Invalid 2",
                Issuer = ca2,
                NotBefore = DateTime.Now.AddDays(1),
                KeyStrength = 1024
            }.BuildX509();

            Assert.False(Utility.VerifyCert(invalidCert4, false, X509RevocationMode.NoCheck, ca2), "Cert 4 is NOT valid with future date");

        }

        [Test]
        public void CreateTestSigningCerts() {
            var ca1 = new CertBuilder { SubjectName = "CN=Test CA1", KeyStrength = 1024 }.BuildX509();
            var intermediate1 = new CertBuilder { SubjectName = "CN=Intermediate 1", Issuer = ca1, KeyStrength = 1024 }.BuildX509();
            var intermediate2 = new CertBuilder { SubjectName = "CN=Intermediate 2", Issuer = intermediate1, KeyStrength = 1024 }.BuildX509();
            var cert1 = new CertBuilder { SubjectName = "CN=Test 1", Issuer = intermediate1, KeyStrength = 1024 }.BuildX509();

            Assert.True(ca1.HasPrivateKey);
            Assert.True(Utility.VerifyCert(ca1, true, X509RevocationMode.NoCheck, null), "CA1 is valid (AllowUnknownCertificateAuthority = true)");

            Assert.False(Utility.VerifyCert(intermediate1, false, X509RevocationMode.NoCheck, null), "Intermediate 1 is not valid when CA not provided, and AllowUnknownCA is false");
            Assert.True(Utility.VerifyCert(intermediate1, false, X509RevocationMode.NoCheck, ca1), "Intermediate 1 is valid with: CA1");

            Assert.True(Utility.VerifyCert(intermediate2, false, X509RevocationMode.NoCheck, ca1, intermediate1), "Intermediate 2 is valid with: CA1.Intermediate1");

            Assert.True(Utility.VerifyCert(cert1, false, X509RevocationMode.NoCheck, ca1, intermediate1), "Cert 1 is valid with: CA1.intermediate1");
            Assert.False(Utility.VerifyCert(cert1, false, X509RevocationMode.NoCheck, ca1, intermediate2), "Cert 1 is NOT valid checked against intermediate 2");

            File.WriteAllBytes($"ca1.pfx", ca1.Export(X509ContentType.Pfx, ""));
            File.WriteAllBytes($"intermediate1.pfx", intermediate1.Export(X509ContentType.Pfx, ""));
            File.WriteAllBytes($"intermediate2.pfx", intermediate2.Export(X509ContentType.Pfx, ""));
            File.WriteAllBytes($"cert1.pfx", cert1.Export(X509ContentType.Pfx, ""));
        }

        [Test]
        public void CertRemovePrivateKey() {
            var ca1 = new CertBuilder { SubjectName = "CN=Test CA1", KeyStrength = 1024 }.BuildCert();
            var ca1Copy = ca1.RemovePrivateKey();

            Assert.True(ca1.HasPrivateKey);
            Assert.False(ca1Copy.HasPrivateKey);
        }
    }
}
