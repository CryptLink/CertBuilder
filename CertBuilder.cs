using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CryptLink.SigningFramework;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace CryptLink {

    /// <summary>
    /// A helper class for generating x509 certificates
    /// </summary>
    public class CertBuilder {

        public string SubjectName { get; set; }
        //public AsymmetricAlgorithm IssuerPrivateKey { get; set; }
        public int KeyStrength { get; set; } = 4096;
        public DateTime NotBefore { get; set; } = DateTime.Now.AddMinutes(-1);
        public DateTime NotAfter { get; set; } = DateTime.Now.AddDays(10);
        public bool IsIntermediate { get; set; } = false;
        public HashProvider SignatureHashProvider { get; set; } = HashProvider.SHA256;

        public X509Certificate2 Issuer { get; set; }
        //{
        //    get {
        //        return _issuer;
        //    }
        //    set
        //    {
        //        if (value != null) {
        //            _issuer = value;
        //            IssuerName = value.IssuerName.Name;

        //            if (value.HasPrivateKey) {
        //                IssuerPrivateKey = value.PrivateKey;
        //            }
        //        }
        //    }
        //}

        public Cert BuildCert() {
            return new Cert(BuildX509());
        }

        public X509Certificate2 BuildX509() {
            CheckParams();

            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certGenerator.SetSerialNumber(serialNumber);

            //ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", Issuer.PrivateKey, random);

            // Signature Algorithm
            var sigString = $"{Enum.GetName(typeof(HashProvider), SignatureHashProvider)}WithRSA";
            certGenerator.SetSignatureAlgorithm(sigString);

            // Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, KeyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            certGenerator.SetSubjectDN(new X509Name(SubjectName));
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            certGenerator.SetPublicKey(subjectKeyPair.Public);
            AsymmetricCipherKeyPair issuerKeyPair = null;

            // Authority Key Identifier
            if (Issuer != null) {
                certGenerator.SetIssuerDN(new X509Name(Issuer.IssuerName.Name));
                var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(DotNetUtilities.FromX509Certificate(Issuer));
                certGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);

                if (Issuer.HasPrivateKey) {
                    var pk = Issuer.PrivateKey;
                    issuerKeyPair = DotNetUtilities.GetKeyPair(pk);
                }
            } else {
                certGenerator.SetIssuerDN(new X509Name(SubjectName));
                issuerKeyPair = subjectKeyPair;
            }

            // Basic Constraints - certificate is allowed to be used as intermediate.
            certGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(IsIntermediate));

            // Valid For
            certGenerator.SetNotBefore(NotBefore);
            certGenerator.SetNotAfter(NotAfter);

            // sign the certificate
            var certificate = certGenerator.Generate(issuerKeyPair.Private, random);

            //return new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            return ConvertBouncyCert(certificate, subjectKeyPair);

        }

        private void CheckParams() {
            if (!SubjectName.StartsWith("CN=")) {
                SubjectName = "CN=" + SubjectName;
            }

            if (Issuer != null && Issuer.HasPrivateKey == false) {
                throw new ArgumentException("Issuer has no private key");
            }
        }

        public X509Certificate2 BuildExperamental() {
            CheckParams();

            var keypairgen = new RsaKeyPairGenerator();
            var secureRandom = new SecureRandom(new CryptoApiRandomGenerator());

            keypairgen.Init(new KeyGenerationParameters(secureRandom, KeyStrength));

            var keypair = keypairgen.GenerateKeyPair();
            var gen = new X509V3CertificateGenerator();

            var CN = new X509Name(SubjectName);
            var SN = BigInteger.ProbablePrime(120, new Random(secureRandom.NextInt()));
            var sigString = $"{Enum.GetName(typeof(HashProvider), SignatureHashProvider)}WithRSA";

            gen.SetSerialNumber(SN);
            gen.SetSubjectDN(CN);
            gen.SetNotAfter(NotAfter);
            gen.SetNotBefore(NotAfter);
            gen.SetSignatureAlgorithm(sigString);
            gen.SetPublicKey(keypair.Public);

            if (Issuer != null) {
                var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(DotNetUtilities.FromX509Certificate(Issuer));
                gen.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);

                gen.SetIssuerDN(new X509Name(Issuer.IssuerName.ToString()));
            } else {
                gen.SetIssuerDN(CN);
            }

            // Basic Constraints - certificate is allowed to be used as intermediate.
            gen.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(IsIntermediate));

            var newCert = gen.Generate(keypair.Private);

            //return new X509Certificate2(DotNetUtilities.ToX509Certificate(newCert));
            return ConvertBouncyCert(newCert, keypair);
        }

        public X509Certificate2 ConvertBouncyCert(Org.BouncyCastle.X509.X509Certificate BouncyCert, AsymmetricCipherKeyPair KeyPair) {
            var pkcs12Store = new Pkcs12Store();
            var certEntry = new X509CertificateEntry(BouncyCert);

            pkcs12Store.SetCertificateEntry(BouncyCert.SerialNumber.ToString(), certEntry);
            pkcs12Store.SetKeyEntry(BouncyCert.SerialNumber.ToString(), 
                new AsymmetricKeyEntry(KeyPair.Private), new[] { certEntry });

            X509Certificate2 keyedCert;

            using (MemoryStream pfxStream = new MemoryStream()) {
                pkcs12Store.Save(pfxStream, null, new SecureRandom());
                pfxStream.Seek(0, SeekOrigin.Begin);
                keyedCert = new X509Certificate2(pfxStream.ToArray());
            }

            return keyedCert;
        }

        //public static X509Certificate2 CreateRoot(string name) {
        //    // Creates a certificate roughly equivalent to 
        //    // makecert -r -n "{name}" -a sha256 -cy authority
        //    // 
        //    using (RSA rsa = RSA.Create()) {
        //        var request = new CertificateRequest(name, rsa, HashAlgorithmName.SHA256);

        //        request.CertificateExtensions.Add(
        //            new X509BasicConstraintsExtension(true, false, 0, true));

        //        // makecert will add an authority key identifier extension, which .NET doesn't
        //        // have out of the box.
        //        //
        //        // It does not add a subject key identifier extension, so we won't, either.
        //        return request.SelfSign(
        //            DateTimeOffset.UtcNow,
        //            // makecert's fixed default end-date.
        //            new DateTimeOffset(2039, 12, 31, 23, 59, 59, TimeSpan.Zero));
        //    }
        //}

        //public static X509Certificate2 CreateTlsClient(string name, X509Certificate2 issuer, SubjectAltNameBuilder altNames) {
        //    using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384)) {
        //        var request = new CertificateRequest(name, ecdsa, HashAlgorithmName.SHA384);

        //        request.CertificateExtensions.Add(
        //            new X509BasicConstraintsExtension(false, false, 0, false));
        //        request.CertificateExtensions.Add(
        //            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));
        //        request.CertificateExtensions.Add(
        //            new X509EnhancedKeyUsageExtension(
        //                new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, false));

        //        if (altNames != null) {
        //            request.CertificateExtensions.Add(altNames.BuildExtension());
        //        }

        //        byte[] serialNumber = new byte[8];

        //        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) {
        //            rng.GetBytes(serialNumber);
        //        }

        //        X509Certificate2 signedCert = request.Sign(
        //            issuer,
        //            TimeSpan.FromDays(90),
        //            serialNumber);

        //        return signedCert.CreateCopyWithPrivateKey(ecdsa);
        //    }
        //}

        //public static X509Certificate2 BuildLocalhostTlsSelfSignedServer() {
        //    SubjectAltNameBuilder sanBuilder = new SubjectAltNameBuilder();
        //    sanBuilder.AddIpAddress(IPAddress.Loopback);
        //    sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
        //    sanBuilder.AddDnsName("localhost");
        //    sanBuilder.AddDnsName("localhost.localdomain");
        //    sanBuilder.AddDnsName(Environment.MachineName);

        //    using (RSA rsa = RSA.Create()) {
        //        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256);

        //        request.CertificateExtensions.Add(
        //            new X509EnhancedKeyUsageExtension(
        //                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        //        request.CertificateExtensions.Add(sanBuilder.BuildExtension());

        //        return request.SelfSign(TimeSpan.FromDays(90));
        //    }
        //}

        //public static byte[] CreateCertificateRenewal(RSA newKey, X509Certificate2 currentCert) {
        //    // Getting, and persisting, `newKey` is out of scope here.

        //    var request = new CertificateRequest(
        //        currentCert.SubjectName,
        //        newKey,
        //        HashAlgorithmName.SHA256);

        //    foreach (X509Extension extension in currentCert.Extensions) {
        //        request.CertificateExtensions.Add(extension);
        //    }

        //    // Send this to the CA you're requesting to sign your certificate.
        //    return request.EncodePkcs10SigningRequest();
        //}

        //public static X509Certificate2 RenewCertificate(X509Certificate2 currentCert) {
        //    using (RSA rsa = RSA.Create()) {
        //        byte[] certificateSigningRequest = CreateCertificateRenewal(rsa, currentCert);

        //        X509Certificate2 signedCertificate = SendRequestToCAAndGetResponse(certificateSigningRequest);

        //        return signedCertificate.CreateCopyWithPrivateKey(rsa);
        //    }
        //}
    }
}
