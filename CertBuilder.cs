using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using CryptLink.SigningFramework;
using System.IO;

namespace CryptLink {

    public class CertBuilder {
        //based on comments from: https://stackoverflow.com/questions/22230745/generate-self-signed-certificate-on-the-fly

        public string SubjectName { set { _subjectName = value; } }

        public string IssuerName { set { _issuerName = value; } }

        public AsymmetricAlgorithm IssuerPrivateKey { set { _issuerPrivateKey = value; } }

        public X509Certificate2 Issuer {
            set {
                if (value != null) {
                    _issuer = value;
                    _issuerName = value.IssuerName.Name;

                    if (value.HasPrivateKey) {
                        _issuerPrivateKey = value.PrivateKey;
                    }
                }
            }
        }

        public int? KeyStrength { set { _keyStrength = value ?? 4096; } }

        public DateTime? NotBefore { set { _notBefore = value; } }

        public DateTime? NotAfter { set { _notAfter = value; } }

        public bool Intermediate { set { _intermediate = value; } }

        private string _subjectName;
        private X509Certificate2 _issuer;
        private string _issuerName;
        private AsymmetricAlgorithm _issuerPrivateKey;
        private int _keyStrength = 4096;
        private DateTime? _notBefore;
        private DateTime? _notAfter;
        private bool _intermediate = true;

        public Cert BuildCert() {
            return new Cert(BuildX509());
        }

        public X509Certificate2 BuildX509() {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            certificateGenerator.SetSignatureAlgorithm("SHA512WithRSA");

            // Issuer and Subject Name
            certificateGenerator.SetIssuerDN(new X509Name(_issuerName ?? _subjectName));
            certificateGenerator.SetSubjectDN(new X509Name(_subjectName));

            // Authority Key Identifier
            if (_issuer != null) {
                var authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(DotNetUtilities.FromX509Certificate(_issuer));
                certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier.Id, false, authorityKeyIdentifier);
            }

            // Basic Constraints - certificate is allowed to be used as intermediate.
            certificateGenerator.AddExtension(X509Extensions.BasicConstraints.Id, true, new BasicConstraints(_intermediate));

            // Valid For
            certificateGenerator.SetNotBefore(_notBefore ?? DateTime.UtcNow.Date);
            certificateGenerator.SetNotAfter(_notAfter ?? DateTime.UtcNow.Date.AddYears(2));

            // Subject Public Key
            var keyGenerationParameters = new KeyGenerationParameters(random, _keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);

            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
            var issuerKeyPair = _issuerPrivateKey == null
                ? subjectKeyPair
                : DotNetUtilities.GetKeyPair(_issuerPrivateKey);

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);

            //return new X509Certificate2(DotNetUtilities.ToX509Certificate(certificate));
            return ConvertBouncyCert(certificate, subjectKeyPair);

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
                keyedCert = new X509Certificate2(pfxStream.ToArray(), "", X509KeyStorageFlags.Exportable);
            }

            return keyedCert;
        }

        private static AsymmetricAlgorithm ConvertToRsaPrivateKey(AsymmetricCipherKeyPair keyPair) {

            var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(keyInfo.PrivateKey.GetDerEncoded());
            if (seq.Count != 9) {
                throw new PemException("malformed sequence in RSA private key");
            }

            var rsa = new RsaPrivateKeyStructure(seq);
            var rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1,
                rsa.Exponent2, rsa.Coefficient);

            return DotNetUtilities.ToRSA(rsaparams);
        }


    }

}
